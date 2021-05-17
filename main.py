#!/usr/bin/env python

# OCP Bug Scry
#
# Given an OCP release version (4.Y.Z), describe the BZs fixed since the
# previous OCP release (4.Y.Z-1).
#
# Requires:
#   - pull-secret for fetching OCP images
#   - valid Kerberos ticket in the REDHAT.COM domain
#   - Bugzilla API Tokern for bugzilla.redhat.com
#   - Python packages `requests`, `requests_kerberos`
#
# TODO:
#  - Figure out how to get the correct packag name to pass to ET
#  - Figure out how to handle subpackages
#  - inspect Cincinatti graph to determine if a release was shipped
#  - inspect Cincinatti graph to determine previously released version
#  - store data in sqlite database
#  - containerize

import argparse
import json
import logging
import os
import subprocess

import requests
from requests_kerberos import HTTPKerberosAuth

OCP_RELEASE_PAYLOAD = "quay.io/openshift-release-dev/ocp-release"
CM_BASE_URL = "https://rhcos-redirector.ci.openshift.org/art/storage/releases/"
BZ_BASE_URL = "https://bugzilla.redhat.com/"


def run_command(cmd):
    '''
    Runs a command and returns the CompletedProcess object

    Parameters:
        cmd (string): Full command to run
    '''
    cmd_proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if cmd_proc.returncode != 0:
        logging.error(cmd_proc.stderr)
        raise SystemExit(1)

    return cmd_proc


def calc_n_minus_one(version):
    '''
    Calculate the N-1 version of an OCP release and returns a string with the
    result

    Parameters:
        version (string): The OCP version to calculate from
    '''
    xyz_ver = version.split('.')
    new_z = int(xyz_ver[2]) - 1
    new_ver = (xyz_ver[0], xyz_ver[1], str(new_z))
    return ".".join(new_ver)


def get_rhcos_version(ocp_version, arch=None, oc_binary=None):
    '''
    Get the RHCOS version of an OCP release

    Parameters:
        ocp_version (string): OCP version to query
        arch (string): The architecture of the OCP version
        oc_binary (string): Location of the oc binary
    '''
    if arch is None:
        arch = "x86_64"

    if oc_binary is None:
        oc_binary = "/usr/local/bin/oc"

    if not os.path.isfile(oc_binary):
        logging.error('Unable to find %s', oc_binary)
        raise SystemExit(1)

    # retrive the machine-os-content spec
    release_payload = OCP_RELEASE_PAYLOAD + ":" + ocp_version + "-" + arch
    moc_cmd = [oc_binary, "adm", "release", "info",
               "--image-for=machine-os-content", release_payload]

    moc_proc = run_command(moc_cmd)
    moc_spec = moc_proc.stdout.strip("\n")

    # retrieve the image info for the m-o-c, then extract the RHCOS version
    moc_json_cmd = [oc_binary, "image", "info", "-o", "json", moc_spec]
    moc_json_proc = run_command(moc_json_cmd)

    moc_json = json.loads(moc_json_proc.stdout)
    rhcos_ver = moc_json['config']['config']['Labels']['version']
    return rhcos_ver


def get_commitmeta(version, baseurl=None, arch=None):
    '''
    Fetches the commitmeta.json for an RHCOS version

    Parameters:
        version (string): RHCOS version to query
        baseurl (string): Base URL to use when fetching the commitmeta.json
        arch (string): Architecture of the RHCOS version
    '''
    if baseurl is None:
        baseurl = CM_BASE_URL

    if arch is None:
        arch = "x86_64"

    # build up URL to commitmeta
    # grab the ocp version, split out to build the `rhcos-4.x` directory,
    # make the url
    ocp_ver = version.split('.')[0]
    rhcos_dir = "rhcos-" + ocp_ver[0] + "." + ocp_ver[1]
    # not strictly safe for URLs, but should work well enough
    cm_url = os.path.join(CM_BASE_URL, rhcos_dir,
                          version, arch, "commitmeta.json")

    cm_req = requests.get(cm_url)
    if not cm_req.ok:
        logging.error(cm_req.reason)
        raise SystemExit(1)

    return cm_req.json()


# Probably don't need the epoch :fingers-crossed:
def make_nvr_list(pkglist):
    '''
    Removes the Epoch and Arch from a list of NEVRAs and returns a list of NVRs

    Parameters:
        pkglist (list): List of package NEVRAs
    '''
    nvrlist = []
    for pkg in pkglist:
        nvr = f'{pkg[0]}-{pkg[2]}-{pkg[3]}'
        nvrlist.append(nvr)

    return nvrlist


def compare_pkglist(new_cm, old_cm):
    '''
    Returns the new list of NEVRAs when comparing the old pkglist to the new
    pkglist.

    Parameters:
        new_cm (dict): JSON of the new commitmeta
        old_cm (dict): JSON of the old commitmeta
    '''
    new_pkglist = new_cm['rpmostree.rpmdb.pkglist']
    old_pkglist = old_cm['rpmostree.rpmdb.pkglist']

    new_nvr_pkglist = make_nvr_list(new_pkglist)
    old_nvr_pkglist = make_nvr_list(old_pkglist)

    pkgdiff = list(set(new_nvr_pkglist) - set(old_nvr_pkglist))

    return sorted(pkgdiff)


def get_fixed_bugs(nvr, et_api_uri):
    '''
    Returns a list of BZ IDs for a package.

    Parameters:
        nvr (string): Package to query errata tool for
        et_api_uri (string): Base URI for Errata Tool API
    '''
    bz_list = []

    build_url = '{}{}{}'.format(et_api_uri, "build/", nvr)
    build_req = requests.get(build_url, auth=HTTPKerberosAuth())
    if not build_req.ok and build_req.reason == "Not Found":
        logging.warning('Unable to find %s in Errata Tool', nvr)
        logging.warning("Possibly using a different RPM name")
        return bz_list

    shipped_errata = []
    for errata in build_req.json()['all_errata']:
        if errata['status'] == "SHIPPED_LIVE":
            shipped_errata.append(errata['id'])

    for errata in shipped_errata:
        errata_url = '{}{}{}'.format(et_api_uri, "erratum/", errata)
        errata_req = requests.get(errata_url, auth=HTTPKerberosAuth())
        if not errata_req.ok:
            logging.warning(errata_url)
            logging.warning(errata_req.reason)
            logging.warning(errata_req.status_code)
            continue
        fixed_bz = errata_req.json()['bugs']['idsfixed']
        bz_list = [bz for bz in fixed_bz if bz not in bz_list]

    return bz_list


def get_bz_description(bug, bz_api_key):
    '''
    Returns the summary field for a BZ

    Parameters:
        bug (string): A Bugzilla ID
        bz_api_key (string): An API key for Bugzilla
    '''
    bz_url = "{}{}{}".format(BZ_BASE_URL, "rest/bug/", bug)
    payload = {'api_key': bz_api_key}
    bz_req = requests.get(bz_url, params=payload)
    if not bz_req.ok:
        logging.warning(bz_url)
        logging.warning(bz_req.reason)
        logging.warning(bz_req.status_code)

    return bz_req.json()['bugs'][0]['summary']


def main():
    '''
    Return a report of BZs fixed in an OCP release.

    Procedure:
      1. Get OCP version from user
      2. Determine previous version (currently just inferring N-1)
      3. Determine changed packages between N-1 -> N
      4. Query Errata Tool for BZs fixed in package version
      5. Query Bugzilla for BZ summaries
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument('ocp_version', help="OCP Version to query")
    parser.add_argument('--arch', help="OCP Architecture", default=None)
    parser.add_argument('--oc-binary', help="Location of oc binary",
                        default=None)
    args = parser.parse_args()

    # this seems less than ideal
    with open("./et_url", 'r') as et_url_f:
        config = et_url_f.read()
        config_s = config.strip()
        if config_s.split('=')[0] == "ET_API_URI":
            et_api_uri = config_s.split('=')[1]
        else:
            logging.error("Unable to determine Errata Tool URI")
            raise SystemExit(1)

    latest_rhcos = get_rhcos_version(ocp_version=args.ocp_version,
                                     arch=args.arch,
                                     oc_binary=args.oc_binary)

    old_ocp = calc_n_minus_one(args.ocp_version)
    old_rhcos = get_rhcos_version(ocp_version=old_ocp,
                                  arch=args.arch,
                                  oc_binary=args.oc_binary)

    print(f'Given OCP release: {args.ocp_version}')
    print(f'\tFound RHCOS version: {latest_rhcos}')
    print(f'Previous OCP version: {old_ocp}')
    print(f'\tPrevious RHCOS version: {old_rhcos}')

    latest_rhcos_cm = get_commitmeta(latest_rhcos)
    old_rhcos_cm = get_commitmeta(old_rhcos)

    pkg_diff = compare_pkglist(latest_rhcos_cm, old_rhcos_cm)

    print(f'New packages versions in {latest_rhcos}:')
    for pkg in pkg_diff:
        print(f'\t{pkg}')

    fixed_bzs = {}
    for pkg in pkg_diff:
        gfb = get_fixed_bugs(pkg, et_api_uri)
        if len(gfb) > 0:
            fixed_bzs[pkg] = gfb

    with open("./bz_creds", 'r') as bz_creds_f:
        api_key = bz_creds_f.read()

    fixed_bz_desc_table = {}
    for pkg, bzs in fixed_bzs.items():
        bz_desc_list = []
        for bug in bzs:
            desc = get_bz_description(bug, api_key)
            bz_desc_list.append("{} {}".format(bug, desc))
        fixed_bz_desc_table[pkg] = bz_desc_list

    for pkg, bzs_descs in fixed_bz_desc_table.items():
        print(f'{pkg}:')
        for desc in bzs_descs:
            print(f'\t{desc}')


if __name__ == "__main__":
    main()

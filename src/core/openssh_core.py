#!/usr/bin/python3


import  os
import  tempfile

def keygen(algo = "rsa", bits = 0, key_format = '',
           usr = "user", hst = "host", debug = 0) :

    """ Function to generate OpenSSH keypair

    This is a stateless function that makes ssh-keygen call and returns the
    generated keypair. It validates user provided inputs before making that
    call and also checks the results of the call before returning from here.

    Parameters
    ----------

    algo        :       str, optional
        Key-type/ algorithm. It comes with a default.

    bits        :       int, optional
        Key-size/ modulus in bits. It comes with a default.

    format      :       str, optional
        Output key-format (PEM/ RFC4716/ PKCS8). It comes with a default.
        Format string is case-insensitive (e.g. both 'PEM' or 'pem' work).

    usr         :       str, optional
        Owner (username) of the keypair (encoded in the output).

    host        :       str, optional
        Hostname of the machine corresponding to the user.


    Returns
    -------
    The method returns a tuple (pri_key, pub_key, errmsg).

    pri_key     :       str
        Text Buffer containing private key in one of the OpenSSH supported
        formats. The buffer is empty when the method encounters an error.

    pub_key     :       str
        Text Buffer containing public key in one of the OpenSSH supported
        formats. The buffer is empty when the method encounters an error.

    errmsg      :       str
        Text buffer which is usually empty when the method is successful.

    """

    bitsize = ""
    bitinfo = ""
    # Input validation
    if (algo.casefold() == "rsa".casefold()) :
        if (0 == bits) :
            pass # special bits value
        elif ((bits < 1024) or (bits % 1024) or (bits > 16384)) :
            msg = 'Invalid modulus bit-size %d for rsa.' % (bits)
            return ('', '', msg)
        else :
            bitsize = '-b %d ' % bits
            bitinfo = '-%db' % bits
    elif (algo.casefold() == "ecdsa".casefold()) :
        if ((bits == 256) or (bits == 384) or (bits == 521)) :
            bitsize = '-b %d ' % bits
            bitinfo = '-%db' % bits
        else :
            msg = 'Invalid bit-size %d for ecdsa' % (bits)
            return ('', '', msg)
    elif ((algo.casefold() == "dsa".casefold())):
        if ((bits != 0) and (bits != 1024)) :
            msg = 'Invalid bit-size %d for dsa' % (bits)
            return ('', '', msg)
        else :
            bitinfo = '-1024b' # fixed for DSA
    elif ((algo.casefold() == "ed25519".casefold())):
          pass
    else :
        msg = 'Invalid algorithm %s or bit-size %d' % (algo, bits)
        return ('', '', msg)

    cmx = ' -C %s@%s:%s%s ' % (usr, hst, algo, bitinfo)

    # key format
    kyfmt = '-m RFC4716 '
    if (len(key_format)) :
        key_format = key_format.upper()
        if ((key_format == "RFC4716") or (key_format == "PEM") or
            (key_format == "PKCS8")) :
            kyfmt = "-m " + key_format;
        else :
            msg = 'Invalid keyformat %s.' % key_format
            return ('', '', msg)

    # Create temporary workspace
    keydir = tempfile.mkdtemp()
    prikey_file = keydir + "/mykey"
    pubkey_file = prikey_file + ".pub"
    stdout_file = prikey_file + ".out"
    stderr_file = prikey_file + ".err"

    # Execute command
    args = {'cbs': 'ssh-keygen -N \"\"',
            'algo': algo.casefold(), 'bts': bitsize, 'cmt': cmx, 'fmx': kyfmt,
            'kfl': prikey_file, 'out': stdout_file, 'err': stderr_file}

    cmd = "{cbs} -t {algo} {bts} {fmx} {cmt} -f {kfl} 1> {out} 2> {err}".\
          format_map(args)

    if (debug > 2) : print(cmd)
    os.system(cmd)

    # Read result
    with open(prikey_file, 'r') as fpri:
        pri_key = fpri.read()
        fpri.close()

    with open(pubkey_file, 'r') as fpub:
        pub_key = fpub.read()
        fpub.close()

    with open(stderr_file, 'r') as ferr:
        err_key = ferr.read()
        ferr.close()

    # return result
    errmsg = ''
    if ((0 == len(pri_key)) or (0 == len(pub_key)) ) :
        errmsg = "ssh-keygen error: " + err_key

    # Clean temporary workspace
    cmd = "rm -fr " + keydir
    os.system(cmd)

    if (4 < debug) :
        print("algo=%s bit-len=%d format=%s\npri-key:\n%s\npub-key:\n%s\n" %
              (algo, bits, key_format, pri_key, pub_key))

    return (pri_key, pub_key, errmsg)
    # keygen ends



def cert_sign(prikey = '', pubkey = '', keyid = "key_id", serial = 0,
              principals = [], vld_from = '', vld_to = '', debug = 0) :

    '''Generates signed OpenSSH certificates from input parameters

    This is a stateless function that uses input private key to sign a
    certificate that will contain input public key. The private key is
    expected to be of the CA while the public key belongs to a host/ user.

    Parameters
    ----------

    prikey      :       str
        Text-buffer containing CA/ signer's private key.

    pubkey      :       str
        Text-buffer containing user/ hosts's public-key which gets
        embedded into the signed certificate.

    keyid       :       str, optional
        Key-identifier, used later by the OpenSSH to track connections.

    serial      :       uint64 (positive), optional
        Serial number used by the CA to issue the certificate. It gets
        encoded into the certificate.

    principals  :       string array, optional
        Array of usernames associated with the certificate. OpenSSH uses
        these from the certificate to enforce login authentication
        restrictions.

    vld_from    :       str, optional
        If vld_from is specified, vld_to must also be specified as well.
        It encodes certificate lifetime. Certificates without these parameters
        are valid perpetually, which is generally not desired. Following
        formats are allowed: -10w, -100w10d, 20111012, 20111012043011
        (YYYYMMDD or YYYYMMDDHHMMSS). Relative times such as -100w (last
        hundred weeks) are encoded using the current time on the machine
        where openssh commands are executed. See man page for ssh-keygen for
        further details.

    vld_to      :       str, optional
        See 'vld_from' above.

    Returns
    -------
        This method returns a tuple, (cert, errormsg)

    cert        :       str
        Text buffer containing signed certificate if the operation was
        successful.

    errormsg    :       str
        Text buffer with any errors encountered, useful especially when
        the 'cert' above is empty.

    '''
    # Input validation
    if ((0 == len(prikey)) or (0 == len(pubkey))) :
        return ('', "Invalid CA-private-key or user/host public-key.")

    validity = ''
    if (len(vld_from)) :
        if (0 == len(vld_to)) :
            msg = "valid-from %s without valid-to value." % vld_from
            return ('', msg)
        else :
            validity = vld_from + ':' + vld_to
    else :
        if (len(vld_to)) :
            validity = ':' + vld_to

    if (len(validity)) : validity = "-V " + validity

    prnarg = ''
    if (len(principals)) :
        prcnt = 0
        for pr in principals :
            if (prcnt) : prnarg += ","
            prnarg += pr
            prcnt += 1
        if (len(prnarg)) : prnarg = "-n \"" + prnarg + "\""

    # Create temporary workspace
    keydir = tempfile.mkdtemp()
    prikey_file = keydir + "/ca_key"
    pubkey_file = keydir + "/key.pub"
    cert_file = keydir + "/key-cert.pub"
    stdout_file = keydir + "/stdout"
    stderr_file = keydir + "/stderr"

    with open(prikey_file, 'wt') as fpri:
        print(prikey, file = fpri)
        fpri.close()
        os.chmod(prikey_file, 0o600)

    with open(pubkey_file, 'wt') as fpub:
        print(pubkey, file = fpub)
        fpub.close()
        os.chmod(pubkey_file, 0o600)

    # Execute command
    args = {'cbs': 'ssh-keygen ',
            'pri': prikey_file, 'pub': pubkey_file, 'kid': keyid,
            'ser': serial, 'vld': validity, 'prn': prnarg,
            'crt': cert_file, 'out': stdout_file, 'err': stderr_file}

    cmd =  "{cbs} -O clear -s {pri} -I \"{kid}\" \
        -z {ser} {vld} {prn} {pub} 1> {out} 2> {err}".format_map(args)

    if (debug > 2) : print(cmd)
    os.system(cmd)

    cert = ''
    with open(cert_file, 'rt') as fcrt:
        cert = fcrt.read()
        fcrt.close()

    std_err = ''
    with open(stderr_file, 'rt') as ferr:
        std_err = ferr.read()
        ferr.close()

    # Clean temporary workspace
    cmd = "rm -fr " + keydir
    os.system(cmd)

    if (0 == len(cert)) :
        msg = "Error signing certificate: " + std_err
        return ('', msg)

    return (cert, '')
    # cert_sign ends


def krlgen(ca_pub = '', rvk_crts = [], rvk_pubs = [],
           rvk_specs = [], debug = 0) :

    '''OpenSSH Key Revocation List (KRL) Generator

    This method takes arrays of OpenSSH certificates/ public-keys or
    key specifications and generates a single KRL as output that
    revokes all the input keys and certificates.

    Parameters
    ----------

    ca_pub      :       str, optional
        Public key of the signing CA. If this is revoked, all certificates
        (NOT the public keys) of the signees get revoked too.

    rvk_crts    :       str, optional
        Array of signed certificates to be revoked.

    rvk_pubs    :       str, optional
        Array of signees' public keys to be revoked

    rvk_specs   :       str, optional
        Array of certificate specifications to be incorporated into the KRL.

    debug       :       int, optional
        Debug flag for extended information in stdout/ stdin.

    Returns
    -------
        This method returns a tuple, (krl, errormsg)

    krl         :       str
        Binary buffer containing OpenSSH KRL.

    errormsg    :       str
        Any error messages encountered during KRL generation. Usually this
        parameter is looked at when the krl is empty.

    '''

    # Input validation
    if ((0 == len(ca_pub)) and (0 == len(rvk_crts)) and
        (0 == len(rvk_pubs)) and (0 == len(rvk_specs))) :
        return (b'', "Nothing to revoke")

    # Create temporary workspace
    keydir = tempfile.mkdtemp()
    ca_pub_file = keydir + "/ca.pub"
    rvk_crt_file = keydir + "/rvk_crts"
    rvk_pub_file = keydir + "/rvk_keys.pub"
    rvk_spec_file = keydir + "/rvk_spec"
    output_file = keydir + "/revocations"
    stdout_file = keydir + "/stdout"
    stderr_file = keydir + "/stderr"

    ca_pub_arg = ''
    if (len(ca_pub)) :
        with open(ca_pub_file, 'wt') as xfile:
            xfile.write(ca_pub)
            xfile.close()
            os.chmod(ca_pub_file, 0o600)
            ca_pub_arg = " " + ca_pub_file

    infiles_arg = ''
    if (len(rvk_crts)) :
        with open(rvk_crt_file, 'wt') as xfile:
            for xbuf in rvk_crts :
                xfile.write(xbuf)
            xfile.close()
            os.chmod(rvk_crt_file, 0o600)
            infiles_arg += " " + rvk_crt_file

    if (len(rvk_pubs)) :
        with open(rvk_pub_file, 'wt') as xfile:
            for xbuf in rvk_pubs :
                xfile.write(xbuf)
            xfile.close()
            os.chmod(rvk_pub_file, 0o600)
            infiles_arg += " " + rvk_pub_file

    if (len(rvk_specs)) :
        with open(rvk_spec_file, 'wt') as xfile:
            for xbuf in rvk_specs :
                xfile.write(xbuf)
            xfile.close()
            os.chmod(rvk_spec_file, 0o600)
            infiles_arg += " " + rvk_spec_file

    # Execute command
    args = {'cbs': 'ssh-keygen ', 'out': output_file,
            'ca': ca_pub_arg, 'in': infiles_arg,
            'sot': stdout_file, 'err': stderr_file}

    cmd =  "{cbs} -k -f {out} {ca} {in} 1> {sot} 2> {err}".format_map(args)

    if (debug > 2) : print(cmd)
    os.system(cmd)

    # Collect output
    outbuf = b''
    with open(output_file, 'rb') as xfile :
        outbuf = xfile.read()
        xfile.close()
        os.chmod(output_file, 0o600)

    # Clean temporary workspace
    cmd = "rm -fr " + keydir
    os.system(cmd)

    return (outbuf, '')
    # krlgen() ends



#####################
#####   Unit Testing
#####################

def utests_keygen(debug = 0) :
    """Unit Tests for OpenSSH key generation

    This tests doesn't have any mandatory inputs. It generates
    various types of openssh keypairs.

    Parameters
    ----------

    debug       :       int, optional
        Debug flag for printing additional details


    Returns
    -------
    This function returns a tuple (total, passed, failed)

    total       :       int
        Total number of tests run by this method

    passed      :       int
        Number of tests that passed

    failed      :       int
        Number of tests that failed

    """

    tests = [
        # a: algorithm, b: bit-size, n: negative test case
        {"a": "ecdsa", "b" : 256, "f": "PEM", "n": 0},
        {"a": "ecdsa", "b" : 384, "f": "JNK", "n": 1},
        {"a": "ecdsa", "b" : 384, "f": "rfc4716", "n": 0},
        {"a": "ecdsa", "b" : 384, "f": "pkcs8", "n": 0},
        {"a": "ecdsa", "b" : 384, "f": "RFC4716", "n": 0},
        {"a": "ecdsa", "b" : 521, "f": "PEM", "n": 0},
        {"a": "ecdsa", "b" : 1024, "f": "PEM", "n": 1},
        {"a": "ed25519", "b" : 0, "f": "PEM", "n": 0},
        {"a": "ed25519", "b" : 0, "f": "RFC4716", "n": 0},
        {"a": "ed25519", "b" : 0, "f": "rfc4716", "n": 0},
        {"a": "ed25519", "b" : 0, "f": "pem", "n": 0},
        {"a": "ed25519", "b" : 0, "f": "pkcs8", "n": 0},
        {"a": "dsa", "b" : 1024, "f": "PEM", "n": 0},
        {"a": "dsa", "b" : 1024, "f": "rfc4716", "n": 0},
        {"a": "dsa", "b" : 1024, "f": "RFC4716", "n": 0},
        {"a": "dsa", "b" : 2048, "f": "PEM", "n": 1},
        {"a": "dsa", "b" : 2048, "f": "pkcs8", "n": 1},
        {"a": "rsa", "b" : 1024, "f": "PEM", "n": 0},
        {"a": "rsa", "b" : 1024, "f": "PKCS8", "n": 0},
        {"a": "rsa", "b" : 2048, "f": "PEM", "n": 0},
        {"a": "rsa", "b" : 2048, "f": "pkcs8", "n": 0},
        {"a": "rsa", "b" : 2048, "f": "rfc4716", "n": 0},
        {"a": "rsa", "b" : 256, "f": "PEM", "n": 1},
        {"a": "rsa", "b" : 256, "f": "pkcs8", "n": 1},
        {"a": "rsa", "b" : 256, "f": "rfc4716", "n": 1},
        {"a": "rsa", "b" : 3072, "f": "PEM", "n": 0},
        {"a": "rsa", "b" : 3072, "f": "pem", "n": 0},
        {"a": "rsa", "b" : 3072, "f": "pkcs8", "n": 0},
        {"a": "rsa", "b" : 3072, "f": "rfc4716", "n": 0},
        {"a": "rsa", "b" : 4096, "f": "PEM", "n": 0},
        {"a": "rsa", "b" : 8192, "f": "PEM", "n": 0},
        {"a": "rsa", "b" : 16384, "f": "PEM", "n": 0},
        {"a": "rsa", "b" : 16384, "f": "pkcs8", "n": 0},
        {"a": "rsa", "b" : 32768, "f": "PEM", "n": 1},
    ]

    tci = 0
    tct = len(tests)
    passed = 0
    failed = 0;
    for tc in tests :
        tci += 1
        # Run the test
        (prk, puk, err) = keygen(algo = tc['a'], bits = tc['b'],
                                 key_format = tc['f'], debug = debug)

        # Check success/ failure
        if ((tc['n'] and len(err)) or ((tc['n'] == 0) and (0 == len(err)))) :
            if (3 < debug) :
                print("%d/%d algo=%s bits=%d negative=%d passed." %
                      (tci, tct, tc['a'], tc['b'], tc['n']))
            passed += 1
        else :
            if (1 < debug) :
                print("%d/%d algo=%s bits=%d negative=%d failed." %
                      (tci, tct, tc['a'], tc['b'], tc['n']))
            failed += 1
            if ((2 < debug) and (len(err))) :
                print("\n%d/%d error=%s\n" % err)

    return (tct, passed, failed)
    # utest_keygen ends

def utests_cert_sign(debug = 0, crtfile = '') :

    """Unit tests for OpenSSH certificate signing logic.

    Parameters
    ----------

    debug       :       int, optional
        Positive integer to display test details. Higher value means
        more details.

    crtfile     :       str, optional
        Name (with or without full-path) of the file in which the test
        will save various generated certificates. This file can be used
        later to decode generated certificates for offline analysis.
        (e.g. "ssh-keygen -L -f <crtfile>").

    Returns
    -------
    This function returns a tuple (total, passed, failed)

    total       :       int
        Total number of tests run by this method

    passed      :       int
        Number of tests that passed

    failed      :       int
        Number of tests that failed

    """

    tests = [
        {
            'ca_alg': 'rsa', 'ca_bits': 3072, 'ca_fmt': 'pem',
            'u_alg': 'rsa', 'u_bits': 2048, 'u_fmt': 'pkcs8',
            'ser': 180, 'kid': 'JohnSmith@intel.com',
            'prn': ['jsmith'],
            'vf': '', 'vt': '',
            'neg': 0
        },
        {
            'ca_alg': 'ed25519', 'ca_bits': 0, 'ca_fmt': 'pem',
            'u_alg': 'rsa', 'u_bits': 4096, 'u_fmt': 'pem',
            'ser': 80, 'kid': 'Abby.Lincon@gmail.com',
            'prn': [],
            'vf': '-4d', 'vt': '',
            'neg': 1
        },
        {
            'ca_alg': 'ed25519', 'ca_bits': 0, 'ca_fmt': 'pem',
            'u_alg': 'dsa', 'u_bits': 1024, 'u_fmt': 'pem',
            'ser': 0x8004112240005000, 'kid': 'John Smith, 1400 Santa Monica, CA 91000',
            'prn': ['johnsmth', 'jsmith'],
            'vf': '-4w', 'vt': '+10w',
            'neg': 0
        },
        {
            'ca_alg': 'ed25519', 'ca_bits': 0, 'ca_fmt': 'pem',
            'u_alg': 'ed25519', 'u_bits': 0, 'u_fmt': 'rfc4716',
            'ser': 5000, 'kid': 'DanielHartman@time.com',
            'vf': '', 'vt': '',
            'prn': ['abbyl', 'root'],
            'neg': 0
        },
        {
            'ca_alg': 'rsa', 'ca_bits': 4096, 'ca_fmt': 'pem',
            'u_alg': 'ed25519', 'u_bits': 0, 'u_fmt': 'rfc4716',
            'ser': 5000, 'kid': 'RickBergman',
            'vf': '20210808000000', 'vt': '20220814103030',
            'prn': ['rickberg', 'rbergman', 'bergmanrick'],
            'neg': 0
        },
        ]

    crt_out = 0
    if (len(crtfile)) :
        fcrt = open(crtfile, 'wt')
        if (False == fcrt.closed) : crt_out = 1

    tci = 0
    tct = len(tests)
    passed = 0
    failed = 0;
    for tc in tests :
        tci += 1
        # Run the test
        (ca_pri, ca_pub, ca_err) = keygen(algo = tc['ca_alg'], bits = tc['ca_bits'],
                                          key_format = tc['ca_fmt'], debug = debug)

        if (0 == len(ca_pri)) :
            if (0 == tc['neg']) : failed += 1
            else : passed +=1
            if (0 < debug) :
                print("%d/%d ca_algo=%s ca_bits=%d fmt=%s negative=%d failed." %
                      (tci, tct, tc['ca_alg'], tc['ca_bits'], tc['ca_fmt'], tc['neg']))
            continue

        (u_pri, u_pub, u_err) = keygen(algo = tc['u_alg'], bits = tc['u_bits'],
                                          key_format = tc['u_fmt'], debug = debug)

        if (0 == len(u_pri)) :
            if (0 == tc['neg']) : failed += 1
            else : passed +=1
            if (0 < debug) :
                print("%d/%d u_algo=%s u_bits=%d fmt=%s negative=%d failed." %
                      (tci, tct, tc['u_alg'], tc['u_bits'], tc['u_fmt'], tc['neg']))
            continue


        (cert, crt_err) = cert_sign(prikey = ca_pri, pubkey = u_pub,
                                    keyid = tc['kid'], vld_from = tc['vf'],
                                    vld_to= tc['vt'], serial = tc['ser'],
                                    principals = tc['prn'],
                                    debug = debug)
        if (0 == len(cert)) :
            if (0 == tc['neg']) : failed += 1
            else : passed += 1
            if (2 < debug) : print("signed-certificate-error:" + crt_err)
        else :
            if (0 == tc['neg']) : passed += 1
            else : failed += 1
            if (crt_out) : print(cert, file = fcrt, end='')
            if (3 < debug) :
                print("signed-certificate:")
                print(cert)

    if (crt_out) : fcrt.close()
    return (tct, passed, failed)
    # utests_cert_sign() ends


def utests_krlgen(debug = 0) :

    """Unit tests for OpenSSH Key Revocation API

    This function runs a series of test vectors against the krlgen() API.

    Parameters
    ----------

    debug       :       int, optional
        Positive integer to print additional information.
        Higher value => more details

    Returns
    -------

    This function returns a tuple (total, passed, failed)

    total       :       int
        Total number of tests run by this method

    passed      :       int
        Number of tests that passed

    failed      :       int
        Number of tests that failed

    """

    import re

    tests = [
                {
                    # ca_algo: CA's keypair algorithm, ca_bits: CA key's bitlength
                    # ca_fmt: Format of CA's keys
                    # r_ca: 0/ 1 Whether to revoke CA's public key in the KRL
                    # neg: 0 / 1 (1 => negative test case that's expected to fail)

                    'ca_algo': 'rsa', 'ca_bits': 3072, 'ca_fmt': 'pem',
                    'r_ca': 1, 'neg': 0,
                    'crts' : [
                        # a: algorithm, b: bit-lengh, f: key-format
                        # r: private-key, u: public-key, c: certificate,
                        # rc: explicitly revoke certificate,
                        # ru: explicitly revoke public key
                        # er_c: expected_certificate_revocation_result (0 / 1)
                        # er_u: expected_pubkey_revocation_result (0 / 1)
                        # fr_c: found revocation status of certificate
                        # fr_u: found revocation status of public key
                                {
                                    'a': 'dsa', 'b': 1024, 'f': 'pkcs8',
                                    'r': '', 'u': '', 'c': '',
                                    'rc': 0, 'ru': 0,
                                    'er_c': 1, 'er_u': 0,
                                    'fr_c': 2, 'fr_u': 2,
                                },
                                {
                                    'a': 'rsa', 'b': 4096, 'f': 'rfc4716',
                                    'r': '', 'u': '', 'c': '',
                                    'rc': 0, 'ru': 0,
                                    'er_c': 1, 'er_u': 0,
                                    'fr_c': 2, 'fr_u': 2,
                                },
                                {
                                    'a': 'ed25519', 'b': 0, 'f': 'pem',
                                    'r': '', 'u': '', 'c': '',
                                    'rc': 0, 'ru': 0,
                                    'er_c': 1, 'er_u': 0,
                                    'fr_c': 2, 'fr_u': 2,
                                },
                                {
                                    'a': 'ecdsa', 'b': 521, 'f': 'pkcs8',
                                    'r': '', 'u': '', 'c': '',
                                    'rc': 0, 'ru': 0,
                                    'er_c': 1, 'er_u': 0,
                                    'fr_c': 2, 'fr_u': 2,
                                },
                        ],
                 },
                 {
                    'ca_algo': 'ed25519', 'ca_bits': 0, 'ca_fmt': 'rfc4716',
                    'r_ca': 0, 'neg': 0,
                    'crts' : [
                                {
                                    'a': 'ecdsa', 'b': 384, 'f': 'pkcs8',
                                    'r': '', 'u': '', 'c': '',
                                    'rc': 0, 'ru': 0,
                                    'er_c': 0, 'er_u': 0,
                                    'fr_c': 2, 'fr_u': 2,
                                },
                                {
                                    'a': 'rsa', 'b': 8192, 'f': 'rfc4716',
                                    'r': '', 'u': '', 'c': '',
                                    'rc': 0, 'ru': 0,
                                    'er_c': 0, 'er_u': 0,
                                    'fr_c': 2, 'fr_u': 2,
                                },
                                {
                                    'a': 'ed25519', 'b': 0, 'f': 'rfc4716',
                                    'r': '', 'u': '', 'c': '',
                                    'rc': 0, 'ru': 0,
                                    'er_c': 0, 'er_u': 0,
                                    'fr_c': 2, 'fr_u': 2,
                                },
                                {
                                    'a': 'dsa', 'b': 0, 'f': 'pkcs8',
                                    'r': '', 'u': '', 'c': '',
                                    'rc': 0, 'ru': 0,
                                    'er_c': 0, 'er_u': 0,
                                    'fr_c': 2, 'fr_u': 2,
                                },
                        ],
                 },
        ]

    tci = 0
    tct = len(tests)
    checked = 0
    passed = 0
    failed = 0;
    for tc in tests :
        tci += 1

        # Run the test case
        ca_pub = ''
        ca_pri = ''

        if (len(tc['crts']) and (0 == len(tc['ca_algo']))) :
            # Can't generate signed certificate withtout CA keys!
            checked += 1
            if (tc['neg']) :
                passed += 1
            else :
                failed += 1
                if (2 < debug) :
                    print("settings-failure=[%d, %d]" % (tci, cxi))
            continue

        if (tc['ca_algo']) :
            # CA keypair/ certificate is part of the test
            (ca_pri, ca_pub, err) = keygen(algo = tc['ca_algo'],
                                           bits = tc['ca_bits'],
                                           key_format = tc['ca_fmt'],
                                           debug = debug)

            if (0 == ca_pri) :
                checked += 1
                if (tc['neg']) : passed += 1
                else : failed += 1
                if (debug > 3) :
                    print("%d/%d ca-key-pair-generation-error: " %
                          (tci, tct, err))
                continue
            else :
                if (debug > 4) :
                    print("%d/%d ca-key-pair-generation-ok" % (tci, tct))
        # 'ca_algo

        crts_pub = [] # Public keys for explicit revocation
        crts_crt = [] # Certificates for explicit revocation

        # Generate signed certificates
        for cx in tc['crts'] :
            (k_pri, k_pub, err) = keygen(algo = cx['a'], bits = cx['b'],
                                         key_format = cx['f'], debug = debug)

            if (0 == len(k_pri)) :
                if (debug > 3) :
                    print("%d/%d crt-key-pair-generation-error: " %
                          (tci, tct, err))
                continue
            else :
                # store key-pair
                cx['r'] = k_pri
                cx['u'] = k_pub
                if (cx['ru']) : crts_pub.append(cert)

                if (len(ca_pri)) :
                    # generate signed certificate
                    (cert, err) = cert_sign(prikey = ca_pri,
                                                pubkey = k_pub,
                                                debug = debug)
                    if (len(cert)) :
                        cx['c'] = cert

                        # check if explicit revocation was requested
                        if (cx['rc']) : crts_crt.append(cert)
                    else :
                        if (debug > 3) :
                            print("%d/%d certificate-generation-error: " %
                                  (tci, tct, err))
            pass # for cx

        ca_pub_r = ''
        if (tc['r_ca']) :
            # Only provide CA public key for revocation if marked in the test
            ca_pub_r = ca_pub

        # Generate the KRL
        (krlbuf, err) = krlgen(ca_pub = ca_pub_r, rvk_crts = crts_crt,
                               rvk_pubs = crts_pub, debug = debug)

        if (4 < debug) : print("krl:{\n" + str(krlbuf) + '}')

        # Create temporary space to create files
        keydir = tempfile.mkdtemp() # Create temporary workspace
        krl_file = keydir + "/krl"
        test_file = keydir + "/check_revocation"
        stdout_file = keydir + "/stdout"
        stderr_file = keydir + "/stderr"

        # save KRL to a file for ssh-keygen
        with open(krl_file, 'wb') as kfile :
            kfile.write(krlbuf)
            kfile.close()
            os.chmod(krl_file, 0o600)

        # Verify revocation status of various items
        cmdbase = "ssh-keygen -Q -f " + krl_file + " "
        cxi = 0
        for cx in tc['crts'] : # cx-verification

            cxi += 1

            # Certificate check
            if (len(cx['c'])) :
                with open(test_file, 'wt') as tfile :
                    tfile.write(cx['c'])
                    tfile.close()
                    os.chmod(test_file, 0o600)

                # 1. Check certificate revocation
                cmd = cmdbase + test_file + " 1> " + stdout_file + \
                        " 2> " + stderr_file
                os.system(cmd)

                result = ''
                with open(stdout_file, 'rt') as ofile :
                    result = ofile.read()
                    ofile.close()

                if (re.search("REVOKED", result, flags=re.IGNORECASE)) :
                    cx['fr_c'] = 1
                elif ((0 == len(result)) or
                       (re.search("ok", result, flags=re.IGNORECASE))) :
                    cx['fr_c'] = 0
                else :
                    cx['fr_c'] = 2

                if (3 < debug) :
                    print("result=[%d, %d]={fr_c=%d, er_c=%d}{%s}" %
                          (tci, cxi, cx['fr_c'], cx['er_c'], result))

                checked += 1
                if (cx['fr_c'] == cx['er_c']) : passed += 1
                else :
                    failed += 1
                    if (2 < debug) :
                        print("cert-failure=[%d, %d]={fr_u=%d, er_u=%d}{%s}" %
                          (tci, cxi, cx['fr_u'], cx['er_u'], result))

            # Public key check
            if (len(cx['u'])) :
                with open(test_file, 'wt') as tfile :
                    tfile.write(cx['u'])
                    tfile.close()
                    os.chmod(test_file, 0o600)

                # 1. Check certificate revocation
                cmd = cmdbase + test_file + " 1> " + stdout_file + \
                        " 2> " + stderr_file
                os.system(cmd)

                result = ''
                with open(stdout_file, 'rt') as ofile :
                    result = ofile.read()
                    ofile.close()

                if (re.search("REVOKED", result, flags=re.IGNORECASE)) :
                    cx['fr_u'] = 1
                elif ((0 == len(result)) or
                       (re.search("ok", result, flags=re.IGNORECASE))) :
                    cx['fr_u'] = 0
                else :
                    cx['fr_u'] = 2

                if (3 < debug) :
                    print("result=[%d, %d]={fr_u=%d, er_u=%d}{%s}" %
                          (tci, cxi, cx['fr_u'], cx['er_u'], result))

                checked += 1
                if (cx['fr_u'] == cx['er_u']) :
                    passed += 1
                else :
                    failed += 1
                    if (2 < debug) :
                        print("pubkey-failure=[%d, %d]={fr_u=%d, er_u=%d}{%s}" %
                          (tci, cxi, cx['fr_u'], cx['er_u'], result))

            pass # cx-verification

        # Clean temporary workspace
        cmd = "rm -fr " + keydir
        os.system(cmd)

    return (checked, passed, failed)
    # utests_krlgen() ends



def usage(prog) :
    """Usage Help

    This function prints various command-line arguments this file can take
    when ran as a standalone Python script from the commandline or interpreter.

    """
    print(prog + " [options ...]\n")
    print("[-c | --crtfile <file>\t(optional output file to store generated certificates)]")
    print("[-d | --debug <level> \t(debug-level-positive-integer)]")
    print("[-h | --help\t(This help message.)]")
    print("\n\n")
    # usage() ends


def main():

    """Entry level function for unit testing this script file.
    """

    import getopt, sys

    try:
        opts, args = getopt.getopt(sys.argv[1:], "c:d:h",
                                   ["crtfile=", "debug=", "help"])

    except getopt.GetoptError as input_err:
        print(input_err)
        usage(sys.argv[0])
        sys.exit(2)

    crtfile = ''        # do not generate certificate file by default
    debug = 2           # default debug level

    for arg, argval in opts:
        if arg in ("-d", "--debug") :
            debug = int(argval)
        elif arg in ("-h", "--help") :
            usage(sys.argv[0])
            sys.exit()
        elif arg in ("-c", "--crtfile"):
            crtfile = argval
        else:
            assert False, "unknown option %s" % arg
    # end-for

    # Unit tests for key-generation
    (total, passed, failed) = utests_keygen(debug = debug)

    if (debug > 0) :
        print("total-keygen-tests=%d passed=%d failed=%d" %
              (total, passed, failed))

    # Unit tests for certificate signing
    (total, passed, failed) = utests_cert_sign(debug = debug, crtfile = crtfile)
    if (debug > 0) :
            print("total-cert_sign-tests=%d passed=%d failed=%d" %
                  (total, passed, failed))

    # Unit tests for KRL generation & verification
    (total, passed, failed) = utests_krlgen(debug = debug)
    if (debug > 0) :
        print("total-krlgen-tests=%d passed=%d failed=%d" %
              (total, passed, failed))

    # main() ends


if __name__ == '__main__' :
    main()


# #############################################################################

#!/usr/bin/env python3

from    flask import Flask, jsonify
import  getopt, requests, sys

# Settings local to the script
__defproto      = "http"
__defhost       = "localhost"
__defport       = 5000

# Debug Levels:
CLDBG_SNGL =  0 # Only print number of failed test cases otherwise 0 on success
CLDBG_SUM  =  1 # Print summary of test cases (total, success, failed)
CLDBG_BFL  =  2 # Print brief info on failures
CLDBG_DFL  =  3 # Print detailed info on failures
CLDBG_DSU  =  4 # Print details on successful cases
CLDBG_EXE  =  5 # Details on test execution
CLDBG_VER1  = 6 # Details' verbosity level-1

__defdebug      = CLDBG_SNGL # Default debug level

def test_norest(url : str, debug = 0) :
    pass
    # test_norest()

def usage(progname) :
    print(progname + " [options]\n")

    print("-d <debuglevel>\t(default=%d)" % __defdebug)
    print("\t\tdebug level, higher value prints more info")

    print("-h | --help\tThis help message.")
    print("-H | --host\tHostname (or IP address)")
    print("-p | --port\t Server's PORT number")
    # usage() ends



def process_input():

    '''Entry level function for unit testing this script file.
    '''

    try:
        opts, args = getopt.getopt(
                        sys.argv[1:], "d:hH:p:",
                        ["debug=", "help", "host", "port"])

    except getopt.GetoptError as input_err:
        print(input_err)
        usage(sys.argv[0])
        sys.exit(2)

    debug = __defdebug
    protocol = __defproto
    portnum = __defport
    hostname = __defhost
    inurl = ''

    for arg, argval in opts:
        if arg in ("-d", "--debug") :
            debug = int(argval)
        elif arg in ("-h", "--help") :
            usage(sys.argv[0])
            sys.exit()
        elif arg in ("-H", "--host") :
            hostname = argval
        elif arg in ("-p", "--port") :
            portnum = int(argval)
        else:
            assert False, "unknown option %s" % arg
    # end-for

    baseurl = protocol + "://" + hostname + ":" + str(portnum)
    inargs = {}
    inargs['baseurl'] = baseurl
    inargs['debug'] = debug
    inargs['errno'] = 0
    return inargs

def test_keygen (inargs) :

    tests = [
                # kt => keytype, kl => keylen, fmt => format
                # ex => Expected outcome (1 => success, 0, failure)
                # ex is set to 0 for negative test cases that are expected to fail.

                {'kt' : 'rsa', 'kl' : 4097, 'fmt'  : 'pem', 'ex' : 0 },
                {'kt' : 'rsa', 'kl' : 3072, 'fmt'  : 'pem', 'ex' : 1 },
                {'kt' : 'ecdsa', 'kl' : 2048, 'fmt'  : 'rfc4716', 'ex' : 0 },
                {'kt' : 'dsa', 'kl' : 256, 'fmt'  : 'rfc4716', 'ex' : 0 },
                {'kt' : 'dsa', 'kl' : 256, 'fmt'  : 'pkcs8', 'ex' : 0 },
                {'kt' : 'dsa', 'kl' : 256, 'fmt'  : 'json', 'ex' : 0 },
                {'kt' : 'dsa', 'kl' : 0, 'fmt'  : 'rfc4716', 'ex' : 1 },
            ]

    myurl       = inargs['baseurl'] + "/keygen"
    debug       = 0
    if 'debug' in inargs : debug = inargs['debug']

    tci = 0
    tct = len(tests)
    passed = 0
    failed = 0;
    for tc in tests :
        tci += 1
        # Run the test
        if (CLDBG_EXE <= debug) :
            print("\n\n\nkeygeneration-test %d/%d" % (tci, tct))

        req_params  = {'keytype' : tc['kt'], 'keylen' : tc['kl'],
                       'format'  : tc['fmt']}

        result      = {'errno': 0, 'errmsg': ""}
        response    = None
        success     = 0

        try :
            if ('method' in inargs) and (inargs['method'] == 'POST') :
                response = requests.post(myurl, json = req_params)
            else :
                # assume GET
                response = requests.get(myurl, json = req_params)

            scode = response.status_code

            if ((300 <= scode) or (200 > scode)) :
                result['errno'] = -2;
                result['errmsg'] = f'HTTP error={scode}'
            else :
                # extract JSON response
                result = response.json()
                if (result['errno'] == 0) : success = 1

        except BaseException as be:
            result['errno'] = -1
            msg = "requests-Exception:" + type(be).__name__
            result['errmsg'] = msg
            if (CLDBG_DFL <= debug) : print("keygen: " + msg)


        # TBD check error code
        if (CLDBG_EXE <= debug) :
            print(response.headers)
            print(response.text)

        expected = "as-expected"
        if (success != tc['ex']) :
            # unexpected outcome
            expected = "unexpectedly"
            failed += 1
        else :
            passed += 1

        if (success) :
            if (CLDBG_DSU <= debug) :
                print("keygeneration-test %d/%d successful %s." %
                      (tci, tct, expected))
        else :
            if (CLDBG_DFL <= debug) :
                print("keygeneration-test %d/%d failed %s. errno=%d errmsg=%s" %
                      (tci, tct, expected, result['errno'], result['errmsg']))
            elif (CLDBG_BFL <= debug) :
                print("keygeneration-test %d/%d failed %s." %
                      (tci, tct, expected))
    # for tests loop

    return (tct, passed, failed)
    # keygen ends

def test_certsign (inargs):
    tests = [
        {
            'ca_alg': 'rsa', 'ca_bits': 3072, 'ca_fmt': 'pem',
            'u_alg': 'rsa', 'u_bits': 2048, 'u_fmt': 'pkcs8',
            'ser': 180, 'kid': 'JohnSmith@intel.com',
            'prn': ['jsmith', 'smithj@jsmith.net'],
            'vf': '', 'vt': '',
            'ex': 1
        },
        {
            'ca_alg': 'ed25519', 'ca_bits': 0, 'ca_fmt': 'rfc4716',
            'u_alg': 'rsa', 'u_bits': 4096, 'u_fmt': 'pkcs8',
            'ser': 7123213908, 'kid': 'JSm@entel.com',
            'prn': ['JSm', 'jsm@jsm.info'],
            'vf': '-1w', 'vt': '+1000w',
            'ex': 1
        },
        ]

    debug       = 0
    if 'debug' in inargs : debug = inargs['debug']

    tci = 0
    tct = len(tests)
    passed = 0
    failed = 0;
    for tc in tests :
        tci += 1
        success = 0

        ##
        # Run the test-case
        #
        if (CLDBG_EXE <= debug) :
            print("\n\n\ncertsign-test %d/%d" % (tci, tct))

        (ca_pub, ca_pri, u_pub, u_pri) = ('', '', '', '')
 
        # Step 1 (Generate CA keypair)

        myurl       = inargs['baseurl'] + "/keygen"

        req_params  = {'keytype' : tc['ca_alg'],
                       'keylen' : tc['ca_bits'],
                       'format'  : tc['ca_fmt']}

        result      = {'errno': 0, 'errmsg': ""}
        response    = None

        try :
            if ('method' in inargs) and (inargs['method'] == 'POST') :
                response = requests.post(myurl, json = req_params)
            else :
                # assume GET
                response = requests.get(myurl, json = req_params)

            scode = response.status_code

            if ((300 <= scode) or (200 > scode)) :
                result['errno'] = -2;
                result['errmsg'] = f'HTTP error={scode}'
            else :
                # extract JSON response
                result = response.json()
                if (result['errno'] == 0) :
                    ca_pub = result['public_key']
                    ca_pri = result['private_key']

        except BaseException as be:
            result['errno'] = -1
            msg = "requests-Exception-1:" + type(be).__name__
            result['errmsg'] += msg
            if (CLDBG_DFL <= debug) : print("keygen: " + msg)

        # Step 2 (Generate User keypair)
        myurl       = inargs['baseurl'] + "/keygen"
        req_params  = {'keytype' : tc['u_alg'],
                       'keylen' : tc['u_bits'],
                       'format'  : tc['u_fmt']}

        result      = {'errno': 0, 'errmsg': ""}
        response    = None

        try :
            if ('method' in inargs) and (inargs['method'] == 'POST') :
                response = requests.post(myurl, json = req_params)
            else :
                # assume GET
                response = requests.get(myurl, json = req_params)

            scode = response.status_code

            if ((300 <= scode) or (200 > scode)) :
                result['errno'] = -2;
                result['errmsg'] += f'HTTP error={scode}'
            else :
                # extract JSON response
                result = response.json()
                if (result['errno'] == 0) :
                    u_pub = result['public_key']
                    u_pri = result['private_key']

        except BaseException as be:
            result['errno'] = -1
            msg = "requests-Exception-2:" + type(be).__name__
            result['errmsg'] += msg
            if (CLDBG_DFL <= debug) : print("keygen: " + msg)

        # Step-3 generate signed certificate IF both CA & user
        # keypairs are intact.
        if ((len(ca_pub) > 0) and (len(ca_pri) > 0) and
           (len(u_pub) > 0) and (len(u_pri) > 0)) :

            myurl       = inargs['baseurl'] + "/certsign"
            req_params  = {'ca_pri' : ca_pri,
                           'u_pub' : u_pub,
                           'serial' : tc['ser'],
                           'keyid' : tc['kid'],
                           'vld_from' : tc['vf'],
                           'vld_till' : tc['vt'],
                           'principals' : tc['prn'],
                           }

            result      = {'errno': 0, 'errmsg': ""}
            response    = None

            try :
                if (('method' in inargs) and
                    (inargs['method'] == 'POST')) :
                    response = requests.post(myurl, json = req_params)
                else :
                    # assume GET
                    response = requests.get(myurl, json = req_params)

                scode = response.status_code

                if ((300 <= scode) or (200 > scode)) :
                    result['errno'] = -2
                    result['errmsg'] += f'HTTP error={scode}'
                else :
                    # extract JSON response
                    result = response.json()
                    if (result['errno'] == 0) :
                        cert = result['cert']
                        success = 1

            except BaseException as be:
                result['errno'] = -1
                msg = "requests-Exception-3:" + type(be).__name__
                result['errmsg'] += msg

        expected = "as-expected"
        if (success != tc['ex']) :
            # unexpected outcome
            expected = "unexpectedly"
            failed += 1
        else :
            passed += 1

        if (success) :
            if (CLDBG_EXE <= debug) :
                print("certsign-test %d/%d successful %s.\n%s\n" %
                      (tci, tct, expected, cert))
            elif (CLDBG_DSU <= debug) :
                print("certsign-test %d/%d successful %s." %
                      (tci, tct, expected))
        else :
            if (CLDBG_DFL <= debug) :
                print("certsign-test %d/%d failed %s. errno=%d errmsg=%s" %
                      (tci, tct, expected, result['errno'], result['errmsg']))
            elif (CLDBG_BFL <= debug) :
                print("certsign-test %d/%d failed %s." %
                      (tci, tct, expected))

    # main-test-loop of certsign() ends

    return (tct, passed, failed)
    # test_certsign ends



#############################################################################################
#############################################################################################
#############################################################################################


def test_krlgen (inargs) :

    tests = [
                {
                    'ca_alg' : 'rsa', 'ca_bits' : 4096, 'ca_fmt'  : 'pem',
                    'r_ca' : 1,
                    'o_pri': '', 'o_pub': '',
                    'crts' : [
                          {
                              'a' : 'ecdsa', 'b': 384, 'f': 'pkcs8',
                              'ser': 100, 'kid': 'JohnSmith@intel.com',
                              'prn': ['jsmith', 'smithj@jsmith.net'],
                              'vf': '', 'vt': '',
                              'rvk' : 1,
                              'o_pri': '', 'o_pub': '', 'o_crt': '',
                          },
                          {
                              'a' : 'rsa', 'b': 3072, 'f': 'pem',
                              'ser': 5000, 'kid': 'JohnSmith@intel.com',
                              'prn': ['jsmith', 'smithj@jsmith.net'],
                              'vf': '', 'vt': '',
                              'rvk' : 1,
                              'o_pri': '', 'o_pub': '', 'o_crt': '',
                          },
                        ],
                    'ex' : 0
                },
                {
                    'ca_alg' : 'ecdsa', 'ca_bits' : 521, 'ca_fmt'  : 'rfc4716',
                    'r_ca' : 0,
                    'o_pri': '', 'o_pub': '',
                    'crts' : [
                          {
                              'a' : 'dsa', 'b': 1024, 'f': 'pem',
                              'ser': 2332948, 'kid': 'JohnSmith@intel.com',
                              'prn': ['jsmith', 'smithj@jsmith.net'],
                              'vf': '', 'vt': '',
                              'rvk' : 1,
                              'o_pri': '', 'o_pub': '', 'o_crt': '',
                          },
                          {
                              'a' : 'rsa', 'b': 4096, 'f': 'pem',
                              'ser': 132, 'kid': 'JohnSmith@intel.com',
                              'prn': ['jsmith', 'smithj@jsmith.net'],
                              'vf': '', 'vt': '',
                              'rvk' : 1,
                              'o_pri': '', 'o_pub': '', 'o_crt': '',
                          },
                        ],
                    'ex' : 0
                },
            ]

    myurl       = inargs['baseurl'] + "/keygen"
    debug       = 0
    if 'debug' in inargs : debug = inargs['debug']

    tci = 0
    tct = len(tests)
    passed = 0
    failed = 0;
    for tc in tests :
        tci += 1
        e_cnt = 0 # encountered errors in this iteration
        # Run the test
        if (CLDBG_EXE <= debug) :
            print("\n\n\nkrl-generation-test %d/%d" % (tci, tct))

        result      = {'errno': 0, 'errmsg': ""}

        # Step 1 (Generate CA keypair)

        myurl       = inargs['baseurl'] + "/keygen"

        req_params  = {'keytype' : tc['ca_alg'],
                       'keylen' : tc['ca_bits'],
                       'format'  : tc['ca_fmt']}

        response    = None

        try :
            if ('method' in inargs) and (inargs['method'] == 'POST') :
                response = requests.post(myurl, json = req_params)
            else :
                # assume GET
                response = requests.get(myurl, json = req_params)

            scode = response.status_code

            if ((300 <= scode) or (200 > scode)) :
                result['errno'] = -2;
                result['errmsg'] = f'HTTP error={scode}'
            else :
                # extract JSON response
                result = response.json()
                if (result['errno'] == 0) :
                    tc['o_pub'] = result['public_key']
                    tc['o_pri'] = result['private_key']

        except BaseException as be:
            result['errno'] = -1
            msg = "requests-Exception-1:" + type(be).__name__
            result['errmsg'] += msg
            e_cnt += 1
            if (CLDBG_DFL <= debug) : print("krlgen: " + msg)

        for tcc in tc['crts'] :
            
            # Step 2 (Generate User keypair)
            myurl       = inargs['baseurl'] + "/keygen"
            req_params  = {'keytype' : tcc['a'],
                           'keylen' : tcc['b'],
                           'format'  : tcc['f']}

            response    = None

            try :
                if ('method' in inargs) and (inargs['method'] == 'POST') :
                    response = requests.post(myurl, json = req_params)
                else :
                    # assume GET
                    response = requests.get(myurl, json = req_params)

                scode = response.status_code

                if ((300 <= scode) or (200 > scode)) :
                    result['errno'] = -2;
                    result['errmsg'] += f'HTTP error={scode}'
                else :
                    # extract JSON response
                    result = response.json()
                    if (result['errno'] == 0) :
                        tcc['o_pub'] = result['public_key']
                        tcc['o_pri'] = result['private_key']

            except BaseException as be:
                result['errno'] = -1
                msg = "requests-Exception-2:" + type(be).__name__
                result['errmsg'] += msg
                e_cnt += 1
                if (CLDBG_DFL <= debug) : print("krlgen: " + msg)
            pass

            # Step-3 generate signed certificate IF both CA & user
            # keypairs are intact.
            if ((len(tc['o_pub']) > 0) and (len(tc['o_pri']) > 0) and
                (len(tcc['o_pub']) > 0) and (len(tcc['o_pri']) > 0)) :

                myurl       = inargs['baseurl'] + "/certsign"
                req_params  = {'ca_pri' : tc['o_pri'],
                               'u_pub' : tcc['o_pub'],
                               'serial' : tcc['ser'],
                               'keyid' : tcc['kid'],
                               'vld_from' : tcc['vf'],
                               'vld_till' : tcc['vt'],
                               'principals' : tcc['prn'],
                              }

                response    = None

                try :
                    if (('method' in inargs) and
                        (inargs['method'] == 'POST')) :
                        response = requests.post(myurl, json = req_params)
                    else :
                        # assume GET
                        response = requests.get(myurl, json = req_params)

                    scode = response.status_code

                    if ((300 <= scode) or (200 > scode)) :
                        result['errno'] = -2
                        result['errmsg'] += f'HTTP error={scode}'
                        msg = "requests-Exception-3:" + type(be).__name__
                        if (CLDBG_DFL <= debug) : print("krlgen: " + msg)
                        e_cnt += 1
                    else :
                        # extract JSON response
                        result = response.json()
                        if (result['errno'] == 0) :
                            tc['o_crt'] = result['cert']

                except BaseException as be:
                    result['errno'] = -1
                    msg = "requests-Exception-4:" + type(be).__name__
                    result['errmsg'] += msg
                    if (CLDBG_DFL <= debug) : print("krlgen: " + msg)
                    e_cnt += 1

                # TBD WIP


        if (0 == e_cnt) :
            passed += 1
        else :
            failed += 1

    # for tests loop

    return (tct, passed, failed)
    # krlgen ends

#############################################################################################
#############################################################################################
#############################################################################################


def main():

    t_total, t_passed, t_failed = (0, 0, 0)

    inargs = process_input()
    baseurl = inargs['baseurl']
    debug = inargs['debug']

    if (CLDBG_EXE <= debug) : print("Accessing: %s" % baseurl)

    # Unit tests for key-generation
    inargs['method'] = 'POST'

    # Key-Generation Tests
    total, passed, failed = test_keygen(inargs)
    t_total += total
    t_passed += passed
    t_failed += failed
    if (CLDBG_EXE <= debug) :
        print ("keygen: total=%d passed=%d failed=%d\n" %
               (total, passed, failed))

    # Certificate signing Tests
    total, passed, failed = test_certsign(inargs)
    t_total += total
    t_passed += passed
    t_failed += failed
    if (CLDBG_EXE <= debug) :
        print ("certsign: total=%d passed=%d failed=%d\n" %
               (total, passed, failed))

    # Key revocation Tests
    total, passed, failed = test_krlgen(inargs)
    t_total += total
    t_passed += passed
    t_failed += failed
    if (CLDBG_EXE <= debug) :
        print ("certsign: total=%d passed=%d failed=%d\n" %
               (total, passed, failed))

    # Final Summary
    if (CLDBG_SUM <= debug) :
        print ("summary: total=%d passed=%d failed=%d" %
               (t_total, t_passed, t_failed))

    return failed

if __name__ == "__main__" :
    failed = main()
    if (failed) : print(failed)

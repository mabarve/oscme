#!/usr/bin/env python3

from flask import Flask, jsonify, request
import getopt, sys
import openssh_core as osc
import oscme_checker as ock
import oscme_webtier as owt

__defport = 5000 # Default debug level
__defhost = '0.0.0.0'

# Client can't set server's debug level so we do it locally.
__defdebug = 5 # Default debug level
__debug = __defdebug # current debug level

app = Flask(__name__)

@app.route("/", methods=['GET', 'POST'])
def stateless_root() :
    return owt.root_handler(stateless = True, debug = __debug)

@app.route('/test', methods=['GET', 'POST'])
def stateless_echo() :
    return owt.web_echo(stateless = True, debug = __debug)


@app.route('/keygen', methods = ['GET', 'POST'])
def stateless_keygen_handler() :
    return owt.keygen_handler(stateless = True, debug = __debug)



@app.route('/certsign', methods = ['GET', 'POST'])
def stateless_certsign_handler() :
    return owt.certsign_handler(stateless = True, debug = __debug)


@app.route('/krlgen', methods = ['GET', 'POST'])
def stateless_krlgen_handler() :
    return owt.krlgen_handler(stateless = True, debug = __debug)


############################################################################

def usage(progname) :
    print(progname + " [options]\n")

    print("-d <debuglevel>\t(default=%d)" % __defdebug)
    print("\t\tdebug level, higher value prints more info")

    print("-h | --help\tThis help message.")
    print("-H | --host\tHostname (or IP address) (default=%s)" %
          __defhost)
    print("-p | --port\tServer's PORT number (default=%d)" %
          __defport)
    print("\n")
    # usage() ends


def process_input():

    try:
        opts, args = getopt.getopt(
                        sys.argv[1:], "d:hH:p:",
                        ["debug=", "help", "host=", "port="])

    except getopt.GetoptError as input_err:
        print(input_err)
        usage(sys.argv[0])
        sys.exit(2)

    debug = __defdebug
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

    inargs = {}
    inargs['debug'] = debug
    inargs['errno'] = 0
    inargs['host'] = hostname
    inargs['port'] = portnum
    return inargs

############################################################################
if __name__ == "__main__" :
    inargs = process_input()
    __debug = inargs['debug']

    print("port=%d host=%s" % (inargs['port'], inargs['host']))

    app.run(debug = True, port = inargs['port'], host = inargs['host'])

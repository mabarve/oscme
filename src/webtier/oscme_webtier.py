#!/usr/bin/python3

from flask import Flask, jsonify, request
import openssh_core as osc
import oscme_checker as ock


def root_handler(stateless = True, debug = 0) :

    mode = mode_str(stateless)

    output = "<html>\n"
    output += "<h1>OSCME Interactive!</h1>\n"
    output += "<h4>This is a " + mode + " server. All the keys (including CA-private) "
    output += "must be provided by the caller for each operation.</h4><hr/>\n"

    result = handle_form_request(request, stateless, debug = debug)
    output += result
    if result : output += "<hr/>\n"

    output += genform_keygen(stateless)
    output += genform_certsign(stateless)

    output += "\n\n</html>\n"
    return output
    # root_handler() ends

def web_echo(stateless = True, debug = 0) :

    mode = mode_str(stateless)

    msg = "Hello stateless anonymous."

    if request.headers.get('Content-Type') != 'application/json' :
        return  "<p>" + msg + "<p><br/>\n"

    if request.method == 'GET' :
        inputs = request.get_json()
        if (None == inputs) :
            # HTML
            msg = "<p>GET (no json input): " + msg + "<p><br/>\n"
        else :
            return jsonify(inputs)

    elif request.method == 'POST' :
        inputs = request.post_json()
        if (None == inputs) :
            return jsonify({'post-result': 'Nil'})
        else :
            print("inputs=[" + inputs + "]")
            return jsonify(inputs)

    return msg
    # web_echo() ends



# ##########################################################################

def mode_str(stateless) :
    mode = "stateful"
    if (stateless) : mode = "stateless";
    return mode

def genform_keygen(stateless = True) :
    action = '/'
    method = 'post'

    output = ''

    output += '<div align=\"center\" >\n'
    output += '<form action=\"{}\" method=\"{}\">\n'.format(action, method)
    output += '<fieldset style=\"width:20%; left:25%;background-color:#FFF8DC\">\n'
    output += '<legend>Generate Keypair</legend>\n'

    output += '<table>\n'

    output += '<tr><td>Algorithm</td><td>\n'
    output += '<select name=\"keytype\" id=\"keytype\" />\n'
    output += '<option value=\"dsa\">DSA</option>\n'
    output += '<option value=\"ecdsa\">ECDSA</option>\n'
    output += '<option value=\"rsa\" selected>RSA</option>\n'
    output += '</select>\n'
    output += '</td></tr>\n'

    output += '<tr><td>Key Length</td><td>\n'
    output += '<select name=\"keylen\" id=\"keylen\" />\n'
    output += '<option value=0>N/A</option>\n'
    output += '<option value=256>256</option>\n'
    output += '<option value=384>384</option>\n'
    output += '<option value=521>521</option>\n'
    output += '<option value=1024>1024</option>\n'
    output += '<option value=2048>2048</option>\n'
    output += '<option value=3072 selected>3072</option>\n'
    output += '<option value=4096>4096</option>\n'
    output += '<option value=8192>8192</option>\n'
    output += '</select>\n'
    output += '</td></tr>\n'

    output += '<tr><td>Key Format</td><td>\n'
    output += '<select name=\"format\" id=\"format\" />\n'
    output += '<option value=\"pem\" selected>PEM</option>\n'
    output += '<option value=\"rfc4716\">RFC4716</option>\n'
    output += '<option value=\"pkcs8\">PKCS8</option>\n'
    output += '<option value=\"json\">JSON</option>\n'
    output += '</select>\n'
    output += '</td></tr>\n'

    output += '<tr><td></td><td>\n'
    output += '<input type=\"hidden\" name=\"oper\" value=\"keygen\" />\n'
    output += '<input type=submit value=submit />&nbsp;&nbsp;&nbsp;&nbsp;\n'
    output += '&nbsp;&nbsp;&nbsp;&nbsp;<input type=reset value=Reset />\n'
    output += '</td></tr>\n'

    output += '</table>\n\n'

    output += '</fieldset>\n'
    output += '</form>\n'
    output += '</div>\n'
    return output



def genform_certsign(stateless = True) :
    action = '/'
    method = 'post'

    def_ca_pri = """\
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
    """

    def_u_pub = """\
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDhCaRJmBuJq92CmpqicjSPgAisUDyGiPPPz2FASSV8KC9/SFWpztKL/iIanjRBgg9kfw8JiflEXCc0WzeAqsYxuWWipIw+Wnx2lfYO6mueRYR4IBwO1ncDbtWlKhjKcxuKDfm3ZoR2doZSNxOYOQAR6EVxx7jziWRriI/jQ3pu2akLT3BV1WruJDSpzguiYwuFQ213PCsv1zj40GLjdfN/F0ajhFJXJzRNXQ141QSTYY7oHJtNWmfR3F8Hl2JgNhoPavkL3MgKYEXR1vn7I+y5tdYzvGb4+ckAksW+5LZTucPoPnj9Cv3MNGlub2gplhedmJ325d0EaiomIJ1kAUVwUNJ+tzo2QzyXbjNYLDdAQxghh958T512zSSneSXI5HxMjykdtoL9PJvjIiArHSrGo2/fgBuzte0s9iu5Ec9huBS/UMOSsTi5Hp9N1WSzsoD+OSBaBjsYgHeLJGStMZnUYVOTu0ak+hcXy4d+uRwo01SEqTmStiv5uEACXQjc0dk= user@host:rsa-3072b
    """

    output = ''

    output += '<div align=\"left\" >\n'
    output += '<form action=\"{}\" method=\"{}\">\n'.format(action, method)
    output += '<fieldset style=\"width:50%; background-color:#F5FFFA\">\n'
    output += '<legend>Generate A Signed Certificate</legend>\n'

    output += '<table align=\"left\">\n'

    output += '<tr><th align=\"right\">Serial#</th>'
    output += '<td align=\"left\"><input name=\"serial\" value=7123213908 /></td></tr>'

    output += '<tr><th align=\"right\">Key ID</th>'
    output += '<td><input name=\"keyid\" value=\"JSm@entel.com\" /></td></tr>'

    output += '<tr><th align=\"right\">Principals</th>'
    output += '<td><input name=\"principals\" value=\"John_Smith\" /></td></tr>'

    output += '<tr><th align=\"right\">Valid From</th>'
    output += '<td><input name=\"vld_from\" value=\"-1d\" /></td></tr>'

    output += '<tr><th align=\"right\">Valid To</th>'
    output += '<td><input name=\"vld_till\" value=\"+90d\" /></td></tr>'

    output += '</table>'

    output += '<table align=\"left\">\n'
    output += '<tr><th>CA-Private-Key</td><th>Target Public Key</td></tr>\n'
    output += '<tr>\n'
    output += '<td><textarea name=\"ca_pri\" '
    # output += ' value=\"{}\" '.format(def_ca_pri)
    output += 'rows=\"10\" cols=\"70\">{}</textarea></td>'.format(def_ca_pri)

    output += '<td><textarea name=\"u_pub\" '
    # output += ' value=\"{}\" '.format(def_u_pub)
    output += ' rows=\"10\" cols=\"70\">{}</textarea></td>'.format(def_u_pub)
    output += '</tr>\n'

    output += '<tr>\n'
    output += '<td><input type=\"hidden\" name=\"oper\" value=\"certsign\" />\n'
    output += '<input type=submit value=submit />'
    output += '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
    output += '<input type=reset value=Reset /></td>\n'
    output += '</td></tr>\n'

    output += '</table>\n\n'

    output += '</fieldset>\n'
    output += '</form>\n'
    output += '</div>\n'
    return output


def handle_form_request(req, stateless = True, debug = 0) :
    output = ''

    if 'oper' in request.form.keys() :
        oper = request.form['oper']
        errors = 0

        if 'keygen' == oper :
            inpt = { 'usr' : 'anonymous', 'host' : 'localhost',}

            if 'keytype' in req.form.keys() :
                inpt['keytype'] = req.form['keytype'].lower()
            else :
                output += "Missing key type.<br/>\n"
                errors += 1
            if 'format' in req.form.keys() :
                inpt['format'] = req.form['format'].lower()
            else :
                output += "Missing key format.<br/>\n"
                errors += 1
            if 'keylen' in req.form.keys() :
                inpt['keylen'] = int(req.form['keylen'])
            else :
                output += "Missing key length.<br/>\n"
                errors += 1

            if 0 < errors :
                return output

            # OSCME API check

            oscme_in = ock.keygen_input(inpt)

            if (oscme_in.major()) :
                if (debug > 3) :
                    output += 'ERROR: oscme_check(major):{}'.format(
                        oscme_in.detailed())

            # Verify parameters & Make the backend call
            (prk, puk, err) = osc.keygen(algo = inpt['keytype'],
                                         bits = inpt['keylen'],
                                         key_format = inpt['format'],
                                         debug = debug)


            if (len(err)) :
                output += 'Error generating keypair:{}<br/>\n'.format(err)
            else :
                output += '<div align=\"center\">\n'
                output += '<fieldset style=\"width:50%; background-color:#F0F8FF\">\n'
                output += '<legend>Generated Keypair</legend>\n'
                output += '<table style=\"width:100%; table-layout:fixed;" >\n'

                output += '<tr><th align=\"left\">'
                space = "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                output += 'Key-Type: {}{}Key-Length:{}{}Format:{}'.format(
                                inpt['keytype'].upper(), space,
                                inpt['keylen'], space,
                                inpt['format'].upper())
                output += '</th></tr>\n'

                output += '<tr><th align=\"left\">Private Key</th></tr>\n'
                output += '<tr><td style=\"word-wrap: break-word;\">'
                output += '<pre>' + prk + '</pre>'
                output += '</td></tr>\n'
                output += '<tr><th align=\"left\">Public Key</th></tr>\n'
                output += '<tr><td style=\"word-wrap: break-word;\">'
                output += puk
                output += '</td></tr>\n'
                output += '</table>\n'
                output += '\n</fieldset>\n</div>\n\n'

        elif 'certsign' == oper :
            inpt = {'ca_pri' : '', 'u_pub' : '', 'serial' : '', 'keyid' : '',
                    'vld_from' : '', 'vld_till': '', 'principals' : ''}

            if 'ca_pri' in req.form.keys() :
                inpt['ca_pri'] = req.form['ca_pri']
            else :
                output += "Missing CA's private key.<br/>\n"
                errors += 1

            if 'u_pub' in req.form.keys() :
                inpt['u_pub'] = req.form['u_pub']
            else :
                output += "Missing Target's public key.<br/>\n"
                errors += 1

            keyset = ['serial', 'keyid', 'vld_from', 'vld_till', 'principals']

            for keyx in keyset :
                if (keyx in req.form.keys()) : inpt[keyx] = req.form[keyx]


            # OSCME API check
            oscme_in = ock.certsign_input(inpt)

            if (oscme_in.major()) :
                if (debug > 3) : print("oscme_check(major): " + oscme_in.detailed())

                # Can not proceed with key-generation. Bail-out
                output += 'Input-Errors={} => ({})<br/>\n'.format(
                                oscme_in.major(), oscme_in.detailed())
                return output

            (cert, crt_err) = osc.cert_sign(prikey = inpt['ca_pri'],
                                            pubkey = inpt['u_pub'],
                                            serial = inpt['serial'],
                                            keyid = inpt['keyid'],
                                            vld_from = inpt['vld_from'],
                                            vld_to = inpt['vld_till'],
                                            principals = inpt['principals'],
                                            debug = debug)

            if (0 < len(crt_err)) :
                output += f'Backend-error: {crt_err}'
                return output
            elif (0 < len(cert)) :
                output += '<div align=\"center\">\n'
                output += '<fieldset style=\"width:50%; background-color:#F0F8FF\">\n'
                output += '<legend>Signed Certificate</legend>\n'
                output += '<table style=\"width:100%; table-layout:fixed;" >\n'

                output += '<tr><td style=\"word-wrap: break-word;\">'
                output += cert
                output += '</th></tr>\n'
                output += '</table>\n'
                output += '\n</fieldset>\n</div>\n\n'
            else :
                output += 'internal error: empty-signed-certificate'
                return output
        else :
                output += 'Error: Requested operation: {} unsupported.<br/>\n'.format(oper)

    return output
    # handle_form_request()

def keygen_handler(stateless = True, debug = 0) :

    '''HTTP JSON handler to generate OpenSSH Keys

    This is a stateless version of the OSCME to generate keys. Generated
    keys are returned to the HTTP Client through JSON response. Keys are
    NOT stored by the server. Input & Output are in JSON format and are
    expected to comply with OSCME RESTful API specification. There is an
    API check logic that verifies the compliance of both input and output
    and logs error messages. Both HTTP GET & POST are supported.

    Parameters
    ----------
    request     HTTP 'request' object containing various HTTP client
                supplied parameters.


    Returns
    -------

    errno       Error code (0 => none), positive integer

    errmsg      Error message (empty when no error)


    public_key  OpenSSH Public Key

    private_key OpenSSH Private Key
    '''


    params = {'keytype' : 'rsa', 'keylen' : 3072,
              'format'  : 'pem', 'usr' : 'anonymous',
              'host' : 'localhost',
             }

    result = {'errno': 1, 'errmsg': 'Unknown-Error',
              'public_key': '', 'private_key': '',
             }

    inputs = {}

    if (request.method == 'GET') or (request.method == 'POST') :
        inputs = request.get_json(silent = True)
    else :
        result['errno'] = -2
        result['errmsg'] = "Unsupported-HTTP-method=" + request.method
        return result

    if (None != inputs) :
        # override defaults
        keyset = ['keytype', 'keylen', 'format']
        for keyx in keyset :
            if (keyx in inputs) : params[keyx] = inputs[keyx]

    # OSCME API check
    oscme_in = ock.keygen_input(params)

    if (oscme_in.major()) :
        if (debug > 3) : print("oscme_check(major): " + oscme_in.detailed())

        # Can not proceed with key-generation. Bail-out
        result['errno'] = -1
        result['errmsg'] = "Input-Errors=%d => (%s)" % \
                           (oscme_in.major(), oscme_in.detailed())
        return result
    elif oscme_in.errors() and (debug > 4) :
        # don't send these to the caller
        print("oscme_check(minor): " + oscme_in.detailed())


    # Verify parameters & Make the backend call
    (prk, puk, err) = osc.keygen(algo = params['keytype'],
                                 bits = params['keylen'],
                                 key_format = params['format'],
                                 debug = debug)

    if (len(err)) :
        result['errno'] = -3
        result['errmsg'] = f'Backend-error: {err}'
    else :
        result['public_key'] = puk
        result['private_key'] = prk
        result['errno'] = 0
        result['errmsg'] = ''

    if (debug > 4) : print(result)

    return jsonify(result)
    # keygen_handler()



def certsign_handler(stateless = True, debug = 0) :

    '''HTTP JSON handler to generate signed OpenSSH certificates, purely
    from user input and no other state in the backend.

    This is a stateless version of the OSCME to generate keys. Generated
    keys are returned to the HTTP Client through JSON response. Keys are
    NOT stored by the server. Input & Output are in JSON format and are
    expected to comply with OSCME RESTful API specification. There is an
    API check logic that verifies the compliance of both input and output
    and logs error messages. Both HTTP GET & POST are supported.

    Parameters
    ----------

    request     HTTP client supplied parameters. It should contain the
                the following ones.

                ca_pri          CA's OpenSSH private key (string, mandatory)
                u_pub           User's OpenSSH public key (string, mandatory)
                serial          uint64, optional
                keyid           string, optional
                vld_from        string, optional
                vld_till        string, optional
                principals      string array, optional (list of names/ email-ids)


    Returns
    -------

    errno       int, error code, integer (0 => no-error)

    errmsg      string, error-message (empty => no-error)

    cert        string, signed OpenSSH certificate

    '''

    print("entering-cert-sign\n\n\n")

    params = {'ca_pri' : '', 'u_pub' : '', 'serial' : '', 'keyid' : '',
              'vld_from' : '', 'vld_till': '', 'principals' : ''
             }

    result = {'errno': 1, 'errmsg': 'unknown-certgen-error', 'cert': ''}

    inputs = {}

    if (request.method == 'GET') or (request.method == 'POST') :
        inputs = request.get_json(silent = True)
    else :
        result['errno'] = -2
        result['errmsg'] = "Unsupported-HTTP-method=" + request.method
        return result

    if (None != inputs) :
        # override defaults
        keyset = ['ca_pri', 'u_pub', 'serial', 'keyid', 'vld_from',
                  'vld_till', 'principals']
        for keyx in keyset :
            if (keyx in inputs) : params[keyx] = inputs[keyx]

    # OSCME API check
    oscme_in = ock.certsign_input(params)

    if (oscme_in.major()) :
        if (debug > 3) : print("oscme_check(major): " + oscme_in.detailed())

        # Can not proceed with key-generation. Bail-out
        result['errno'] = -1
        result['errmsg'] = "Input-Errors=%d => (%s)" % \
                           (oscme_in.major(), oscme_in.detailed())
        return result
    elif oscme_in.errors() and (debug > 4) :
        # don't send these to the caller
        print("oscme_check(minor): " + oscme_in.detailed())

    (cert, crt_err) = osc.cert_sign(prikey = params['ca_pri'],
                                    pubkey = params['u_pub'],
                                    serial = params['serial'],
                                    keyid = params['keyid'],
                                    vld_from = params['vld_from'],
                                    vld_to = params['vld_till'],
                                    principals = params['principals'],
                                    debug = debug)

    if (0 < len(crt_err)) :
        result['errno'] = -3
        result['errmsg'] = f'Backend-error: {crt_err}'
    elif (0 < len(cert)) :
        result['cert'] = cert
        result['errno'] = 0
        result['errmsg'] = ''
    else :
        result['errno'] = -4
        result['errmsg'] = 'unknown-backend-err'

    return jsonify(result)
    # certsign_handler() ends



def krlgen_handler(stateless = True, debug = 0) :

    '''HTTP JSON handler to generate OpenSSH Keys

    This is a stateless version of the OSCME to generate keys. Generated
    keys are returned to the HTTP Client through JSON response. Keys are
    NOT stored by the server. Input & Output are in JSON format and are
    expected to comply with OSCME RESTful API specification. There is an
    API check logic that verifies the compliance of both input and output
    and logs error messages. Both HTTP GET & POST are supported.

    Parameters
    ----------


    Returns
    -------


    '''

    print("entering-krl-gen\n\n\n")

    params = {'ca_pub' : '', 'rvk_crts' : [],
              'rvk_pubs' : [], 'rvk_specs' : [], }

    result = {'errno': 1, 'errmsg': 'unknown-certgen-error', 'cert': ''}

    inputs = {}

    if (request.method == 'GET') or (request.method == 'POST') :
        inputs = request.get_json(silent = True)
    else :
        result['errno'] = -2
        result['errmsg'] = "Unsupported-HTTP-method=" + request.method
        return result

    if (None != inputs) :
        # override defaults
        keyset = ['ca_pub', 'rvk_crts', 'rvk_pubs', 'rvk_specs', ]
        for keyx in keyset :
            if (keyx in inputs) : params[keyx] = inputs[keyx]

    # :TODO: OSCME API check
    # oscme_in = ock.certsign_input(params)
    # if (oscme_in.major()) :
    #    if (debug > 3) : print("oscme_check(major): " + oscme_in.detailed())

        # Can not proceed with key-generation. Bail-out
        # result['errno'] = -1
        # result['errmsg'] = "Input-Errors=%d => (%s)" % \
        #                   (oscme_in.major(), oscme_in.detailed())
        # return result
    # elif oscme_in.errors() and (debug > 4) :
        # don't send these to the caller
        # print("oscme_check(minor): " + oscme_in.detailed())

    (krl, krl_err) = osc.krlgen(ca_pub = params['ca_pub'],
                                rvk_crts = params['rvk_crts'],
                                rvk_pubs = params['rvk_pubs'],
                                rvk_specs = params['rvk_specs'],
                                debug = debug)

    if (0 < len(krl_err)) :
        result['errno'] = -3
        result['errmsg'] = f'Backend-error: {krl_err}'
    elif (0 < len(krl)) :
        result['krl'] = krl
        result['errno'] = 0
        result['errmsg'] = ''
    else :
        result['errno'] = -4
        result['errmsg'] = 'unknown-backend-err'

    return jsonify(result)
    # krlgen_handler() ends

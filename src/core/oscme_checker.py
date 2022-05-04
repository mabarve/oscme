#!/usr/bin/python3


class checker_base(object) :

    def __init__(self) :
        self.reset()

    def reset(self) :
        self.result = {'errors' : 0, 'major': 0, 'details': []}
        return self.result

    def errors(self) :
        return self.result['errors']

    def major(self) :
        cnt = self.result['major']
        return self.result['major']

    def minor(self) :
        return self.errors() - self.major()

    def brief(self) :
        msg = ""
        msg += "errors=%d" % self.result['errors']

        major = self.result['major']
        if (major > 0) : msg += ", major=%d" % major

        return msg

    def detailed(self) :
        msg = self.brief()

        cc = 0
        msg += " ["
        for cx in self.result['details'] :
            if (0 < cc) : msg += ", "
            msg +=      "msg[%d]={code=%d major=%s msg=[%s]}" % \
                        (cc, cx['code'], cx['major'], cx['msg'])
            cc += 1
        msg += "]"

        return msg

    def str(self) :
        return self.brief()

    def __str__(self) :
        return self.str()
    # class checker_base ends


class certsign_input(checker_base) :

    '''
    Updates/ holds results of OSCME API compliance check for cert-signing request
    '''

    def check(self, params) :

        '''Check OSCME API compliance of HTTP request.

        The OSCME API checks are the same regardless of the type of OSCME
        server (stateful vs. stateless). This routine is called by web-handlers
        *after* they have successfully converted the input data to 'params',
        which is a Python dictionary. Output is also a dictionary whose format
        is explained in the following note.


        This routine checks API compliance as per the OSCME specification. It's
        supposed to be a definitive reference for API compliance verification.
        However it doesn't guarantee implementation support for all features.
        For example, 'ecdsa' may be a valid parameter in the API specification
        but a particular OSCME implementation may NOT support this algorithm.
        Checks for implementation support are outside the scope of this routine.

        This checker runs in a greedy manner; i.e. it doesn't return upon
        encountering the first error but rather tries to find additional
        errors as far as it can.


        Parameters
        ----------

        ca_pri     str
                        CA's private-key in PEM/ RFC4716/ RKCS8 formats. This key
                        is used to digitally sign the OpenSSH certificate.

        u_pub      str
                        User/Host key in PEM/ RFC4716/ RKCS8 formats. This key is
                        is embedded in the signed certificate.

        serial     str, optional
                        Serial Number to be embedded into the certificate

        keyid      str, optional
                        Key-Identifier to be embedded into the certificate

        principals str, optional
                        List of strings of the owner's name/ identification on
                        different machines.

        vld_from   str, optional
                        If specified must be accompanied with vld_till. It's the
                        start-date of the certificate. See 'ssh-keygen' for
                        acceptable formats.

        vld_till   str, optional
                        If specified must be accompanied with vld_from. It's the
                        expiration-date of the certificate. See 'ssh-keygen' for
                        acceptable formats.

        Returns
        -------

        Returns an array of dictionaries & some error counts:

        '''

        ca_pri = ''
        if (not ('ca_pri' in params)) :
            msg = "missing-ca-private-key"
            add_msg(self.result, -1, True, msg)
        else :
            ca_pri = params['ca_pri']

        if (0 >= len(ca_pri)) :
            msg = "empty-ca-private-key"
            add_msg(self.result, -1, True, msg)

        u_pub = ''
        if (not ('u_pub' in params)) :
            msg = "missing-user-public-key"
            add_msg(self.result, -1, True, msg)
        else :
            u_pub = params['u_pub']

        if (0 >= len(u_pub)) :
            msg = "empty-user-public-key"
            add_msg(self.result, -1, True, msg)

        vld_cnt = 0
        vld_from = vld_till = ''

        if ('vld_from' in params) and (0 < len(params['vld_from'])) :
            vld_cnt += 1
            vld_from = params['vld_from']
        if ('vld_till' in params) and (0 < len(params['vld_till'])) :
            vld_cnt += 1
            vld_till = params['vld_till']

        if not vld_cnt in [0, 2] :
            msg = "both-vld-times-must-be-specified cnt=%d" % vld_cnt
            add_msg(self.result, -1, True, msg)

        return self.errors()
        # check ends


    def __init__(self, params = None) :
        checker_base.__init__(self)
        if (None != params) : self.check(params)

    # class api_check_result ends




class keygen_input (checker_base) :

    '''Updates/ holds results of OSCME API compliance check


    '''

    def check(self, params) :

        '''Check OSCME API compliance of HTTP request.

        The OSCME API checks are the same regardless of the type of OSCME
        server (stateful vs. stateless). This routine is called by web-handlers
        *after* they have successfully converted the input data to 'params',
        which is a Python dictionary. Output is also a dictionary whose format
        is explained in the following note.


        This routine checks API compliance as per the OSCME specification. It's
        supposed to be a definitive reference for API compliance verification.
        However it doesn't guarantee implementation support for all features.
        For example, 'ecdsa' may be a valid parameter in the API specification
        but a particular OSCME implementation may NOT support this algorithm.
        Checks for implementation support are outside the scope of this routine.

        This checker runs in a greedy manner; i.e. it doesn't return upon
        encountering the first error but rather tries to find additional
        errors as far as it can.

        Parameters
        ----------

        keytype     str
                        {rsa/ dsa/ ecdsa}
                        case-sensitive strings with only one of the values above.

        keylen      int     >= 0

        format      str
                        {pem/ rfc4716/ pkcs8} case-sensitive strings

        username    str, optional
                        Owner's name can be encoded in the key.


        hostname    str, optional
                        Owner's hostname can be encoded in the key.


        Returns
        -------

        Returns an array of dictionaries & some error counts:

        returns =   {
                        # 'errors'    : >= 0 total errors encountered
                        # 'major'     : >= 0 total major errors
                        # 'details'   : Array of error messages
                        # 'code'      : negative integer
                        # 'major'     : True of it' a major error
                        # 'msg'       : Details of error message

                        'errors' : 2, 'major': 1, 'minor': 1,
                        'details' : [ {'code' : -1, 'major' : 0, 'msg' : "message"}, ]
                    }


        '''

        if ('keytype' in params) and ('keylen' in params) and ('format' in params) :
            kt = params['keytype'].lower()
            kl = params['keylen']
            kf = params['format'].lower()

            # Now check keylen against key-type & length combinations
            if (kt == 'rsa') :
                if (0 != (kl % 1024)) :
                    # not divisible by 1024
                    msg = "invalid-RSA-keylen: %d" % kl
                    add_msg(self.result, -1, True, msg)
            elif (kt == 'dsa') :
                if (not ((kl == 0) or (kl == 1024))) :
                    msg = "invalid-DSA-keylen: %d" % kl
                    add_msg(self.result, -1, True, msg)
            elif (kt == 'ecdsa') :
                if (not ((kl == 256) or (kl == 384) or (kl == 521))) :
                    msg = "invalid-ECDSA-keylen: %d" % kl
                    add_msg(self.result, -1, True, msg)
            elif (kt == 'ed25519') :
                if (not (kl == 0)) :
                    msg = "nonzero-ed25519-keylen: %d" % kl
                    add_msg(self.result, -1, True, msg)
            else :
                msg = "invalid-keytype: " + kt
                add_msg(self.result, -1, True, msg)

            # Check for format
            if not ((kf == 'pem') or (kf == 'rfc4716') or (kf == 'pkcs8')) :
                msg = "invalid-key-format: " + kf
                add_msg(self.result, -1, True, msg)

        else :
            # Missing keytype
            if (not 'keytype' in params) :
                msg = "missing-keytype"
                add_msg(self.result, -1, True, msg)
            if (not 'keylen' in params) :
                msg = "missing-keylen"
                add_msg(self.result, -1, True, msg)
            if (not 'format' in params) :
                msg = "missing-format"
                add_msg(self.result, -1, True, msg)


        return self.errors()
        # check ends

    def __init__(self, params = None) :
        checker_base.__init__(self)
        if (None != params) : self.check(params)

    # class api_check_result ends


def add_msg(result, code, major, msg) :

    if ('errors' in result) :
        result['errors'] += 1
    else :
        result['errors'] = 1

    if (major and 'major' in result) :
        result['major'] += 1
    else :
        result['major'] = 1

    entry = {'code': code, 'major': major, 'msg' : msg}

    if 'details' in result :
        if (len(list(result['details'])) > 0) :
            result['details'].append(entry)
        else :
            result['details'] = [entry]

        return True # added
    else :
        return False # Couldn't add

    # add_msg ends

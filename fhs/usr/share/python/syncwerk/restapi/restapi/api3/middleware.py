import urllib

class DecodeFilePathMiddleware(object):
    """This for decode file path param in url to enable exec operation file/dir has special charater
    """    

    def update_request_param(self, request_data, param, data):
        # remember old state
        _mutable = request_data._mutable

        # set to mutable
        request_data._mutable = True

        request_data[param] = data

        request_data._mutable = _mutable

    def process_request(self, request):
        # Params that will be decoded
        PATH_PARAMS = ['p', 'path','dir_path','base','fn' ,'q']
        
        for PARAM in PATH_PARAMS:
            path = request.GET.get(PARAM, None)
            if path:
                path = urllib.unquote(path)
                self.update_request_param(request.GET, PARAM, path)
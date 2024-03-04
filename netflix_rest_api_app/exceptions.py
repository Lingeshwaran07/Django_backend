from rest_framework.exceptions import APIException

from rest_framework import status 

class CustomAPIException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'A custom API exception occurred.'

    def __init__(self, detail=None, status_code=None):
        if detail is not None:
            self.detail = detail
        if status_code is not None:
            self.status_code = status_code
        super().__init__(detail,status_code)    

import os
from typing import Union

def readEnvVar(EnvVar: str, DefaultValue: Union[None,str] = None) -> Union[str,dict]:

    if (EnvVar not in os.environ):
        if (DefaultValue == None):
            return {"ErrorCode":"100","ErrorMsg":"The environment variable '{0}' is not defined.".format(EnvVar)}
        else:
            return DefaultValue
    return os.environ[EnvVar]
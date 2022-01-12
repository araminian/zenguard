import yaml
import os , sys
def parseYAML(YAMLFile):
    if os.path.exists(YAMLFile):
        try:
            with open(YAMLFile) as file:
                configuration = {}
                configuration = yaml.load(file, Loader=yaml.FullLoader)
        except IOError as e:
            Error = {"ErrorCode":"505","ErrorMsg":"I/O error({0}): {1}".format(e.errno, e.strerror)}
        except:
            Error = {"ErrorCode":"505","ErrorMsg":sys.exc_info()[1]}
            return Error
        else:       
            return configuration
    else:
        Error = {"ErrorCode":"404","ErrorMsg":"Config File not found"}
        return Error
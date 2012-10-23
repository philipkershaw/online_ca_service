"""
Class Factory and module import utility

Contrail project
"""
__author__ = "Philip Kershaw"
__date__ = "15/02/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import traceback
import logging, os, sys
log = logging.getLogger(__name__)


def import_module_object(module_name, object_name=None, object_type=None):
    '''Import from a string module name and object name.  _object can be
    any entity contained in a module
    
    @param module_name: _name of module containing the class
    @type module_name: str 
    @param object_name: _name of the class to import.  If none is given, the 
    class name will be assumed to be the last component of modulePath
    @type object_name: str
    @rtype: class object
    @return: imported class'''
    if object_name is None:
        if ':' in module_name:
            # Support Paste style import syntax with rhs of colon denoting 
            # module content to import
            _module_name, object_name = module_name.rsplit(':', 1)
            if '.' in object_name:
                object_name = object_name.split('.')
        else: 
            try:
                _module_name, object_name = module_name.rsplit('.', 1)
            except ValueError:
                raise ValueError('Invalid module name %r set for import: %s' %
                                 (module_name, traceback.format_exc()))        
    else:
        _module_name = module_name
        
    if isinstance(object_name, basestring):
        object_name = [object_name]
    
    log.debug("Importing %r ..." % object_name) 
      
    module = __import__(_module_name, globals(), locals(), [])
    components = _module_name.split('.')
    try:
        for component in components[1:]:
            module = getattr(module, component)
    except AttributeError:
        raise AttributeError("Error importing %r: %s" %
                             (object_name, traceback.format_exc()))

    imported_object = module
    for i in object_name:
        imported_object = getattr(imported_object, i)

    # Check class inherits from a base class
    if object_type and not issubclass(imported_object, object_type):
        raise TypeError("Specified class %r must be derived from %r; got %r" %
                        (object_name, object_type, imported_object))
    
    log.info('Imported %r from module, %r', object_name, _module_name)
    return imported_object


def call_module_object(module_name, object_name=None, module_filepath=None, 
                       object_type=None, object_args=None, 
                       object_properties=None):
    '''
    Create and return an instance of the specified class or invoke callable
    @param module_name: _name of module containing the class
    @type module_name: str 
    @param object_name: _name of the class to instantiate.  May be None in 
    which case, the class name is parsed from the module_name last element
    @type object_name: str
    @param module_filepath: Path to the module - if unset, assume module on 
    system path already
    @type module_filepath: str
    @param object_properties: dict of properties to use when instantiating the 
    class
    @type object_properties: dict
    @param object_type: expected type for the object to instantiate - to 
    enforce use of specific interfaces 
    @type object_type: object
    @return: object - instance of the class specified 
    '''
    
    # ensure that properties is a dict - NB, it may be passed in as a null
    # value which can override the default val
    if not object_properties:
        object_properties = {}

    if not object_args:
        object_args = ()
        
    # variable to store original state of the system path
    sys_path_bak = None
    try:
        try:
            # Module file path may be None if the new module to be loaded
            # can be found in the existing system path            
            if module_filepath:
                if not os.path.exists(module_filepath):
                    raise IOError("Module file path '%s' doesn't exist" % 
                                  module_filepath)
                          
                # Temporarily extend system path ready for import
                sys_path_bak = sys.path
                          
                sys.path.append(module_filepath)

            
            # Import module name specified in properties file
            imported_object = import_module_object(module_name, 
                                                   object_name=object_name,
                                                   object_type=object_type)
        finally:
            # revert back to original sys path, if necessary
            # NB, python requires the use of a try/finally OR a try/except 
            # block - not both combined
            if sys_path_bak:
                sys.path = sys_path_bak
                            
    except Exception, e:
        log.error('%r module import raised %r type exception: %r' % 
                  (module_name, e.__class__, traceback.format_exc()))
        raise 

    # Instantiate class
    log.debug('Instantiating object "%s"', imported_object.__name__)
    try:
        if object_args:
            obj = imported_object(*object_args, **object_properties)
        else:
            obj = imported_object(**object_properties)
            
        return obj

    except Exception, e:
        log.error("Instantiating module object, %r: %r" % 
                                                    (imported_object.__name__, 
                                                     traceback.format_exc()))
        raise
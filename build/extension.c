#include <php.h>
#include <Zend/zend_API.h>
#include <Zend/zend_hash.h>
#include <Zend/zend_types.h>
#include <stddef.h>

#include "extension.h"
#include "extension_arginfo.h"
#include "_cgo_export.h"


PHP_MINIT_FUNCTION(extension) {
    
    return SUCCESS;
}

zend_module_entry extension_module_entry = {STANDARD_MODULE_HEADER,
                                         "extension",
                                         ext_functions,             /* Functions */
                                         PHP_MINIT(extension),  /* MINIT */
                                         NULL,                      /* MSHUTDOWN */
                                         NULL,                      /* RINIT */
                                         NULL,                      /* RSHUTDOWN */
                                         NULL,                      /* MINFO */
                                         "1.0.0",                   /* Version */
                                         STANDARD_MODULE_PROPERTIES};

PHP_FUNCTION(Realtime_start)
{
    if (zend_parse_parameters_none() == FAILURE) {
        RETURN_THROWS();
    }
    int result = start();
    RETURN_BOOL(result);
}

PHP_FUNCTION(Realtime_broadcast)
{
    zend_string *message = NULL;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(message)
    ZEND_PARSE_PARAMETERS_END();
    broadcast(message);
}


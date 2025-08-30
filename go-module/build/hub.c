#include <php.h>
#include <Zend/zend_API.h>
#include <Zend/zend_hash.h>
#include <Zend/zend_types.h>
#include <stddef.h>

#include "hub.h"
#include "hub_arginfo.h"
#include "_cgo_export.h"


PHP_MINIT_FUNCTION(hub) {
    
    return SUCCESS;
}

zend_module_entry hub_module_entry = {STANDARD_MODULE_HEADER,
                                         "hub",
                                         ext_functions,             /* Functions */
                                         PHP_MINIT(hub),  /* MINIT */
                                         NULL,                      /* MSHUTDOWN */
                                         NULL,                      /* RINIT */
                                         NULL,                      /* RSHUTDOWN */
                                         NULL,                      /* MINFO */
                                         "1.0.0",                   /* Version */
                                         STANDARD_MODULE_PROPERTIES};

PHP_FUNCTION(broadcast)
{
    zend_string *message = NULL;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(message)
    ZEND_PARSE_PARAMETERS_END();
    broadcast(message);
}


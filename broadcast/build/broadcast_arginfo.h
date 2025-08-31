/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: f92a37c0da8dff6afcbef2b457d2321c5fdef226 */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_broadcast, 0, 2, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, channel, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, message, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_FUNCTION(broadcast);

static const zend_function_entry ext_functions[] = {
	ZEND_FE(broadcast, arginfo_broadcast)
	ZEND_FE_END
};

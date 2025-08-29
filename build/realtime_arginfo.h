/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: db0674f7f473c847a9fbdf54833d976d7a2f7d47 */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_Realtime_start, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_Realtime_broadcast, 0, 1, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, message, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_FUNCTION(Realtime_start);
ZEND_FUNCTION(Realtime_broadcast);

static const zend_function_entry ext_functions[] = {
	ZEND_RAW_FENTRY(ZEND_NS_NAME("Realtime", "start"), zif_Realtime_start, arginfo_Realtime_start, 0, NULL, NULL)
	ZEND_RAW_FENTRY(ZEND_NS_NAME("Realtime", "broadcast"), zif_Realtime_broadcast, arginfo_Realtime_broadcast, 0, NULL, NULL)
	ZEND_FE_END
};

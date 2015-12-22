LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := libcrypto
LOCAL_SRC_FILES := $(TARGET_ARCH_ABI)/libcrypto.a
include $(PREBUILT_STATIC_LIBRARY)

LOCAL_MODULE := xts
LOCAL_MODULE_FILENAME := libxts
LOCAL_STATIC_LIBRARIES := crypto
LOCAL_LDLIBS := -llog
LOCAL_SRC_FILES := xtslib.c jni.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/openssl/include
include $(BUILD_SHARED_LIBRARY)

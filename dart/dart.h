#pragma once

#ifdef WIN32
#define EXPORT extern "C" __declspec(dllexport)
#else
#define EXPORT extern "C" __attribute__((visibility("default"))) __attribute__((used))
#endif

EXPORT struct FrameSize {
	uint32_t width = 0;
	uint32_t height = 0;
};

EXPORT struct Array {
	uint8_t* data = nullptr;
	uint64_t size = 0;
	FrameSize frameSize;
};

EXPORT void init();
EXPORT uint64_t readFrame(unsigned char** data);
EXPORT Array readFrame2();
EXPORT Array readFrame3();
EXPORT void freeFrame(unsigned char* data);
EXPORT Array randomFunc();
EXPORT void deinit();
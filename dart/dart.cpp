#include <iostream>

#include "mfmediaengine.h"
#include "mfapi.h"
#include "mfreadwrite.h"

#include <Dbt.h>
#include <ks.h>
#include <ksmedia.h>
#include <vector>
#include <comdef.h>
#include <algorithm>
#include "dart.h"
#include <fstream>
#include <string>
#include <sstream>
#include <chrono>

#pragma comment (lib, "ole32.lib")
#pragma comment (lib, "mf.lib")
#pragma comment (lib, "mfplat.lib")
#pragma comment (lib, "mfuuid.lib")
#pragma comment (lib, "mfreadwrite.lib")

class Logger {
public:
    Logger(const std::string& filepath) :
        outstream(filepath, std::ios::out) {
    }

    void log(const std::string& msg, const char* file = __FILE__, int line = __LINE__) {
        std::stringstream stream = getCurrentTime();
        outstream << stream.str() << msg << "\n" << std::flush;
    }
private:
    std::stringstream getCurrentTime() {
        using namespace std::chrono;
        auto highResNow = high_resolution_clock::now();
        auto fractionalPart = duration_cast<microseconds>(highResNow.time_since_epoch()).count() % 1000000;
        auto now = system_clock::now();
        auto time = system_clock::to_time_t(now);
        std::tm calendarTime;
        localtime_s(&calendarTime, &time);
        std::stringstream ss;
        ss << std::put_time(&calendarTime, "[ %d-%m-%Y %H:%M:%S.") << fractionalPart << " ] ";
        return ss;
    }

    std::ofstream outstream;
};

static Logger logger = Logger("log.log");

static bool success(HRESULT result) {
    if (SUCCEEDED(result)) {
        return true;
    }
    _com_error err(result);
    LPCTSTR errMsg = err.ErrorMessage();
    std::wcout << errMsg << '\n';
    return false;
}



template <typename T>
struct ComDeleter {
    void operator()(T* ptr) {
        if (ptr != nullptr) {
            ptr->Release();
        }
    }
};

template <typename T>
struct CoTaskDeleter {
    void operator()(T* ptr) {
        if (ptr != nullptr) {
            CoTaskMemFree(reinterpret_cast<void*>(ptr));
        }
    }
};

template<typename T>
using UniqueComPtr = std::unique_ptr<T, ComDeleter<T>>;

template<typename T>
using UniqueCoTaskPtr = std::unique_ptr<T, CoTaskDeleter<T>>;

template<typename T>
constexpr UniqueComPtr<T> nullComPtr() {
    return std::unique_ptr<T, ComDeleter<T>>(nullptr);
}

template<typename T>
constexpr UniqueCoTaskPtr<T> nullCoTaskPtr() {
    return std::unique_ptr<T, CoTaskDeleter<T>>(nullptr);
}

UniqueComPtr<IMFAttributes> createAttributes() {
    IMFAttributes* pAttributes = nullptr;
    HRESULT hr = MFCreateAttributes(&pAttributes, 1);
    if (!success(hr)) {
        return nullComPtr<IMFAttributes>();
    }
    return UniqueComPtr<IMFAttributes>(pAttributes);
}

std::vector<UniqueComPtr<IMFActivate>> createDeviceEnum(const UniqueComPtr<IMFAttributes>& attributes) {
    IMFActivate** devicesPtr = nullptr;
    UINT32 count = 0;
    HRESULT hr = MFEnumDeviceSources(attributes.get(), &devicesPtr, &count);

    if (!success(hr)) {
        return {};
    }
    std::vector<UniqueComPtr<IMFActivate>> devices;
    for (int i = 0; i < count; i++) {
        devices.emplace_back(UniqueComPtr<IMFActivate>(devicesPtr[i]));
    }
    CoTaskMemFree(devicesPtr);
    return devices;
}

UniqueComPtr<IMFMediaSource2> createMediaSource(const UniqueComPtr<IMFActivate>& device) {
    IMFMediaSource2* pMediaSource = nullptr;
    void** voidMediaSource = reinterpret_cast<void**>(&pMediaSource);
    success(device->ActivateObject(__uuidof(IMFMediaSource), voidMediaSource));
    HRESULT hr = device->ActivateObject(__uuidof(IMFMediaSource2), voidMediaSource);
    if (!success(hr)) {
        return nullComPtr<IMFMediaSource2>();
    }
    return UniqueComPtr<IMFMediaSource2>(pMediaSource);
}

UniqueComPtr<IMFSourceReader> createSourceReader(const UniqueComPtr<IMFMediaSource2>& mediaSource) {
    IMFSourceReader* reader = nullptr;
    HRESULT hr = MFCreateSourceReaderFromMediaSource(mediaSource.get(), NULL, &reader);
    if (!success(hr)) {
        return nullComPtr<IMFSourceReader>();
    }
    return UniqueComPtr<IMFSourceReader>(reader);
}

UniqueComPtr<IMFMediaType> getCurrentMediaType(const UniqueComPtr<IMFSourceReader>& reader) {
    IMFMediaType* type = nullptr;
    HRESULT hr = reader->GetCurrentMediaType(MF_SOURCE_READER_FIRST_VIDEO_STREAM, &type);
    if (!success(hr)) {
        return nullComPtr<IMFMediaType>();
    }
    return UniqueComPtr<IMFMediaType>(type);
}

FrameSize getFrameSize(const UniqueComPtr<IMFMediaType>& mediaType) {
    FrameSize frameSize;
    UINT64 frameSizeUINT64;
    HRESULT hr = mediaType->GetUINT64(MF_MT_FRAME_SIZE, &frameSizeUINT64);
    if (!success(hr)) {
        return frameSize;
    }
    frameSize.width = static_cast<UINT32>(frameSizeUINT64 >> 32);
    frameSize.height = static_cast<UINT32>(frameSizeUINT64);
    return frameSize;
}

GUID getMediaFormat(const UniqueComPtr<IMFMediaType>& mediaType) {
    GUID format;
    HRESULT hr = mediaType->GetGUID(MF_MT_SUBTYPE, &format);
    if (!success(hr)) {
        return GUID{ 0, 0, 0, 0 };
    }
    return format;
}

UniqueComPtr<IMFSample> readSampleBlockingMode(const UniqueComPtr<IMFSourceReader>& reader) {
    IMFSample* sample = nullptr;
    DWORD stream;
    DWORD flags;
    LONGLONG timestamp;
    for (;;) {
        // this is reading in syncronous blocking mode, MF supports also async calls
        HRESULT hr = reader->ReadSample(MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0, &stream, &flags, &timestamp, &sample);
        if (flags & MF_SOURCE_READERF_STREAMTICK) {
            continue;
        }
        break;
    }
    return UniqueComPtr<IMFSample>(sample);
}

UniqueComPtr<IMFMediaBuffer> getContignousBuffer(const UniqueComPtr<IMFSample>& sample) {
    IMFMediaBuffer* buffer = nullptr;
    HRESULT hr = sample->ConvertToContiguousBuffer(&buffer);
    if (!success(hr)) {
        return nullComPtr<IMFMediaBuffer>();
    }
    return UniqueComPtr<IMFMediaBuffer>(buffer);
}

std::vector<unsigned char> convertYUY2ToRGBA24(BYTE* yuy2, DWORD size) {
    std::vector<unsigned char> rgb24;
    rgb24.reserve(size * 1.5);

    for (int i = 0; i < size; i += 4) {
        int y0 = yuy2[i];
        int u0 = yuy2[i + 1];
        int y1 = yuy2[i + 2];
        int v0 = yuy2[i + 3];

        int c = y0 - 16;
        int d = u0 - 128;
        int e = v0 - 128;

        rgb24.push_back(std::clamp((298 * c + 516 * d + 128) >> 8, 0, 255)); //blue
        rgb24.push_back(std::clamp((298 * c - 100 * d - 208 * e + 128) >> 8, 0, 255)); //green
        rgb24.push_back(std::clamp((298 * c + 409 * e + 128) >> 8, 0, 255)); //red
        rgb24.push_back(255); //alpha

        c = y1 - 16;
        rgb24.push_back(std::clamp((298 * c + 516 * d + 128) >> 8, 0, 255)); //blue
        rgb24.push_back(std::clamp((298 * c - 100 * d - 208 * e + 128) >> 8, 0, 255)); //green
        rgb24.push_back(std::clamp((298 * c + 409 * e + 128) >> 8, 0, 255)); //red
        rgb24.push_back(255); //alpha
    }
    return rgb24;
}

void convertYUY2ToRGBA24Ptr(unsigned char* dst, BYTE* yuy2, DWORD size) {
    int j = 0;
    for (int i = 0; i < size; i += 4) {
        int y0 = yuy2[i];
        int u0 = yuy2[i + 1];
        int y1 = yuy2[i + 2];
        int v0 = yuy2[i + 3];

        int c = y0 - 16;
        int d = u0 - 128;
        int e = v0 - 128;

        dst[j] = std::clamp((298 * c + 516 * d + 128) >> 8, 0, 255); //blue
        dst[j + 1] = std::clamp((298 * c - 100 * d - 208 * e + 128) >> 8, 0, 255); //green
        dst[j + 2] = std::clamp((298 * c + 409 * e + 128) >> 8, 0, 255); //red
        dst[j + 3] = 255; //alpha

        c = y1 - 16;
        dst[j + 4] = std::clamp((298 * c + 516 * d + 128) >> 8, 0, 255); //blue
        dst[j + 5] = std::clamp((298 * c - 100 * d - 208 * e + 128) >> 8, 0, 255); //green
        dst[j + 6] = std::clamp((298 * c + 409 * e + 128) >> 8, 0, 255); //red
        dst[j + 7] = 255; //alpha
        j += 8;
    }
}

template <typename F>
void runOnBufferData(const UniqueComPtr<IMFMediaBuffer>& buffer, F&& functor) {
    static_assert(std::is_invocable_v<F, BYTE*, DWORD>, "Functor must be invocable with BYTE* and DWORD arguments");
    BYTE* data;
    DWORD size = 0;
    HRESULT hr = buffer->Lock(&data, NULL, &size);
    functor(data, size);
    buffer->Unlock();
}

void writeToBitmap(const std::vector<unsigned char>& rgb24Data, const FrameSize& frameSize) {
    HANDLE file;
    BITMAPFILEHEADER fileHeader{};
    BITMAPINFOHEADER fileInfo{};
    DWORD write = 0;

    file = CreateFile(L"sample.bmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    fileHeader.bfType = 19778;
    fileHeader.bfSize = sizeof(fileHeader.bfOffBits) + sizeof(RGBTRIPLE);
    fileHeader.bfReserved1 = 0;
    fileHeader.bfReserved2 = 0;
    fileHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

    fileInfo.biSize = sizeof(BITMAPINFOHEADER);
    fileInfo.biWidth = frameSize.width;
    fileInfo.biHeight = frameSize.height;
    fileInfo.biPlanes = 1;
    fileInfo.biBitCount = 24;
    fileInfo.biCompression = BI_RGB;
    fileInfo.biSizeImage = frameSize.width * frameSize.height * (24 / 8);
    fileInfo.biXPelsPerMeter = 2400;
    fileInfo.biYPelsPerMeter = 2400;
    fileInfo.biClrImportant = 0;
    fileInfo.biClrUsed = 0;

    WriteFile(file, &fileHeader, sizeof(fileHeader), &write, NULL);
    WriteFile(file, &fileInfo, sizeof(fileInfo), &write, NULL);
    WriteFile(file, rgb24Data.data(), fileInfo.biSizeImage, &write, NULL);

    CloseHandle(file);
}

static UniqueComPtr<IMFSourceReader> reader = nullptr;
static FrameSize frameSize = FrameSize{};

void init() {
    success(CoInitialize(nullptr));
    auto attributes = createAttributes();
    success(attributes->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE, MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID));
    auto devices = createDeviceEnum(attributes);
    auto mediaSource = createMediaSource(devices[0]);
    reader = createSourceReader(mediaSource);
    auto currentType = getCurrentMediaType(reader);
    frameSize = getFrameSize(currentType);
}

uint64_t readFrame(unsigned char** data) {
    logger.log("Before reader check");
    if (reader == nullptr) {
        return 0;
    }
    logger.log("Before sample get");
    auto sample = readSampleBlockingMode(reader);
    logger.log("Before buffer get");
    auto buffer = getContignousBuffer(sample);
    logger.log("Before rgb24 get");
    std::vector<unsigned char> rgb24(frameSize.width * frameSize.height * 24);
    logger.log("Before runOnBuffer");
    runOnBufferData(buffer, [&](BYTE* data, DWORD size) {
        logger.log("Before convert");
        rgb24 = convertYUY2ToRGBA24(data, size);
        }
    );
    logger.log("Before malloc");
    auto ptr = new unsigned char[rgb24.size()];
    logger.log("Before memcpy");
    memcpy(ptr, rgb24.data(), rgb24.size() * sizeof(unsigned char));
    logger.log("Before data");
    data = &ptr;
    logger.log("Before return");
    return rgb24.size();
}

Array readFrame2() {
    logger.log("Before reader check");
    if (reader == nullptr) {
        return Array{};
    }
    logger.log("Before sample get");
    auto sample = readSampleBlockingMode(reader);
    logger.log("Before buffer get");
    auto buffer = getContignousBuffer(sample);
    logger.log("Before rgb24 get");
    std::vector<unsigned char> rgba24(frameSize.width * frameSize.height * 24);
    logger.log("Before runOnBuffer");
    runOnBufferData(buffer, [&](BYTE* data, DWORD size) {
        logger.log("Before convert");
        rgba24 = convertYUY2ToRGBA24(data, size);
        }
    );
    logger.log("Before malloc");
    Array arr{};
    arr.data = new unsigned char[rgba24.size()];
    logger.log("Before memcpy");
    memcpy(arr.data, rgba24.data(), rgba24.size() * sizeof(unsigned char));
    arr.size = rgba24.size();
    arr.frameSize = frameSize;
    return arr;
}


Array readFrame3() {
    if (reader == nullptr) {
        return Array{};
    }
    auto sample = readSampleBlockingMode(reader);
    auto buffer = getContignousBuffer(sample);
    Array arr{};
    runOnBufferData(buffer, [&](BYTE* data, DWORD size) {
            arr.data = new unsigned char[2 * size];
            convertYUY2ToRGBA24Ptr(arr.data, data, size);
            arr.size = 2 * size;
        }
    );
    arr.frameSize = frameSize;
    return arr;
}

void freeFrame(unsigned char* data) {
    delete[] data;
}

Array randomFunc() {
    Array arr{};
    arr.data = new unsigned char[20];
    for (int i = 0; i < 20; i++) {
        arr.data[i] = i * 2;
    }
    arr.size = 20;
    return arr;
}

void deinit() {
    reader.reset();
}
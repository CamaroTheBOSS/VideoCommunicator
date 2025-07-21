#include "video.h"

#include <algorithm>

namespace video {
    UniqueComPtr<IMFCollection> createEmptyCollection() {
        IMFCollection* collection = nullptr;
        HRESULT hr = MFCreateCollection(&collection);
        if (!success(hr)) {
            return nullComPtr<IMFCollection>();
        }
        return UniqueComPtr<IMFCollection>(collection);
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

    UniqueComPtr<IMFMediaSource> createAggregateMediaSource(const UniqueComPtr<IMFCollection>& mediaSources) {
        IMFMediaSource* pMediaSource = nullptr;
        void** voidMediaSource = reinterpret_cast<void**>(&pMediaSource);
        HRESULT hr = MFCreateAggregateSource(mediaSources.get(), &pMediaSource);
        if (!success(hr)) {
            return nullComPtr<IMFMediaSource>();
        }
        return UniqueComPtr<IMFMediaSource>(pMediaSource);
    }

    UniqueComPtr<IMFSourceReader> createSourceReader(const UniqueComPtr<IMFMediaSource2>& mediaSource) {
        IMFSourceReader* reader = nullptr;
        HRESULT hr = MFCreateSourceReaderFromMediaSource(mediaSource.get(), NULL, &reader);
        if (!success(hr)) {
            return nullComPtr<IMFSourceReader>();
        }
        return UniqueComPtr<IMFSourceReader>(reader);
    }

    UniqueComPtr<IMFSourceReader> createSourceReader(const UniqueComPtr<IMFMediaSource>& mediaSource) {
        IMFSourceReader* reader = nullptr;
        HRESULT hr = MFCreateSourceReaderFromMediaSource(mediaSource.get(), NULL, &reader);
        if (!success(hr)) {
            return nullComPtr<IMFSourceReader>();
        }
        return UniqueComPtr<IMFSourceReader>(reader);
    }

    UniqueComPtr<IMFSinkWriter> createSourceWriter(const UniqueComPtr<IMFMediaSink>& mediaSink) {
        IMFSinkWriter* writer = nullptr;
        HRESULT hr = MFCreateSinkWriterFromMediaSink(mediaSink.get(), NULL, &writer);
        if (!success(hr)) {
            return nullComPtr<IMFSinkWriter>();
        }
        return UniqueComPtr<IMFSinkWriter>(writer);
    }

    UniqueComPtr<IMFMediaSink> createEmptyMediaSink() {
        IMFMediaSink* sink = nullptr;
        HRESULT hr = MFCreateAudioRenderer(nullptr, &sink);
        if (!success(hr)) {
            return nullComPtr<IMFMediaSink>();
        }
        return UniqueComPtr<IMFMediaSink>(sink);
    }

    UniqueComPtr<IMFStreamSink> getStreamSinkByIndex(const int idx, const UniqueComPtr<IMFMediaSink>& mediaSink) {
        IMFStreamSink* sink = nullptr;
        HRESULT hr = mediaSink->GetStreamSinkByIndex(idx, &sink);
        if (!success(hr)) {
            return nullComPtr<IMFStreamSink>();
        }
        return UniqueComPtr<IMFStreamSink>(sink);
    }

    UniqueComPtr<IMFMediaType> getMediaTypeByIndex(const int idx, const UniqueComPtr<IMFMediaTypeHandler>& typeHandler) {
        IMFMediaType* type = nullptr;
        HRESULT hr = typeHandler->GetMediaTypeByIndex(idx, &type);
        if (!success(hr)) {
            return nullComPtr<IMFMediaType>();
        }
        return UniqueComPtr<IMFMediaType>(type);
    }

    UniqueComPtr<IMFMediaTypeHandler> getMediaTypeHandler(const UniqueComPtr<IMFStreamSink>& streamSink) {
        IMFMediaTypeHandler* typeHandler = nullptr;
        HRESULT hr = streamSink->GetMediaTypeHandler(&typeHandler);
        if (!success(hr)) {
            return nullComPtr<IMFMediaTypeHandler>();
        }
        return UniqueComPtr<IMFMediaTypeHandler>(typeHandler);
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

    SampleData readSampleBlockingMode(const UniqueComPtr<IMFSourceReader>& reader) {
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
        SampleData sampleData{
            .sample = UniqueComPtr<IMFSample>(sample),
            .type = SampleType::video,
            .stream = stream,
            .flags = flags,
            .timestamp = timestamp
        };
        sampleData.sample->GetSampleDuration(&sampleData.duration);
        sampleData.sample->GetSampleTime(&sampleData.presentationTime);
        return sampleData;
    }

    SampleData readAudioSampleBlockingMode(const UniqueComPtr<IMFSourceReader>& reader) {
        IMFSample* sample = nullptr;
        DWORD stream;
        DWORD flags;
        LONGLONG timestamp;
        for (;;) {
            // this is reading in syncronous blocking mode, MF supports also async calls
            HRESULT hr = reader->ReadSample(MF_SOURCE_READER_FIRST_AUDIO_STREAM, 0, &stream, &flags, &timestamp, &sample);
            if (flags & MF_SOURCE_READERF_STREAMTICK) {
                continue;
            }
            break;
        }
        SampleData sampleData{
            .sample = UniqueComPtr<IMFSample>(sample),
            .type = SampleType::audio,
            .stream = stream,
            .flags = flags,
            .timestamp = timestamp
        };
        sampleData.sample->GetSampleDuration(&sampleData.duration);
        sampleData.sample->GetSampleTime(&sampleData.presentationTime);
        return sampleData;
    }

    UniqueComPtr<IMFMediaBuffer> getContignousBuffer(const UniqueComPtr<IMFSample>& sample) {
        IMFMediaBuffer* buffer = nullptr;
        HRESULT hr = sample->ConvertToContiguousBuffer(&buffer);
        if (!success(hr)) {
            return nullComPtr<IMFMediaBuffer>();
        }
        return UniqueComPtr<IMFMediaBuffer>(buffer);
    }

    std::vector<unsigned char> convertYUY2ToRGB24(BYTE* yuy2, DWORD size) {
        std::vector<unsigned char> rgb24;
        rgb24.reserve(size * 1.5);

        for (int row = 0; row < 360; row++) {
            for (int col = row * size; col < 640; col += 4) {
                int i = row * size + col;
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

                c = y1 - 16;
                rgb24.push_back(std::clamp((298 * c + 516 * d + 128) >> 8, 0, 255)); //blue
                rgb24.push_back(std::clamp((298 * c - 100 * d - 208 * e + 128) >> 8, 0, 255)); //green
                rgb24.push_back(std::clamp((298 * c + 409 * e + 128) >> 8, 0, 255)); //red
            }
        }
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

            c = y1 - 16;
            rgb24.push_back(std::clamp((298 * c + 516 * d + 128) >> 8, 0, 255)); //blue
            rgb24.push_back(std::clamp((298 * c - 100 * d - 208 * e + 128) >> 8, 0, 255)); //green
            rgb24.push_back(std::clamp((298 * c + 409 * e + 128) >> 8, 0, 255)); //red
        }
        return rgb24;
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
}

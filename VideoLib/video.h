#pragma once

#include "custom_types.h"
#include <vector>

namespace video {
    enum class SampleType { audio, video };
    struct SampleData {
        UniqueComPtr<IMFSample> sample;
        SampleType type;
        unsigned long stream;
        unsigned long flags;
        long long timestamp;
        long long duration;
        long long presentationTime;
    };

    UniqueComPtr<IMFCollection> createEmptyCollection();
    UniqueComPtr<IMFAttributes> createAttributes();
    std::vector<UniqueComPtr<IMFActivate>> createDeviceEnum(const UniqueComPtr<IMFAttributes>& attributes);
    UniqueComPtr<IMFMediaSource2> createMediaSource(const UniqueComPtr<IMFActivate>& device);
    UniqueComPtr<IMFMediaSource> createAggregateMediaSource(const UniqueComPtr<IMFCollection>& mediaSources);
    UniqueComPtr<IMFSourceReader> createSourceReader(const UniqueComPtr<IMFMediaSource2>& mediaSource);
    UniqueComPtr<IMFSourceReader> createSourceReader(const UniqueComPtr<IMFMediaSource>& mediaSource);
    UniqueComPtr<IMFSinkWriter> createSourceWriter(const UniqueComPtr<IMFMediaSink>& mediaSink);
    UniqueComPtr<IMFMediaSink> createEmptyMediaSink();
    UniqueComPtr<IMFStreamSink> getStreamSinkByIndex(const int idx, const UniqueComPtr<IMFMediaSink>& mediaSink);
    UniqueComPtr<IMFMediaType> getMediaTypeByIndex(const int idx, const UniqueComPtr<IMFMediaTypeHandler>& typeHandler);
    UniqueComPtr<IMFMediaTypeHandler> getMediaTypeHandler(const UniqueComPtr<IMFStreamSink>& streamSink);
    UniqueComPtr<IMFMediaType> getCurrentMediaType(const UniqueComPtr<IMFSourceReader>& reader);
    FrameSize getFrameSize(const UniqueComPtr<IMFMediaType>& mediaType);
    GUID getMediaFormat(const UniqueComPtr<IMFMediaType>& mediaType);
    SampleData readSampleBlockingMode(const UniqueComPtr<IMFSourceReader>& reader);
    SampleData readAudioSampleBlockingMode(const UniqueComPtr<IMFSourceReader>& reader);
    UniqueComPtr<IMFMediaBuffer> getContignousBuffer(const UniqueComPtr<IMFSample>& sample);
    std::vector<unsigned char> convertYUY2ToRGB24(BYTE* yuy2, DWORD size);
    void writeToBitmap(const std::vector<unsigned char>& rgb24Data, const FrameSize& frameSize);

    template <typename F>
    void runOnBufferData(const UniqueComPtr<IMFMediaBuffer>& buffer, F&& functor) {
        static_assert(std::is_invocable_v<F, BYTE*, DWORD>, "Functor must be invocable with BYTE* and DWORD arguments");
        BYTE* data;
        DWORD size = 0;
        HRESULT hr = buffer->Lock(&data, NULL, &size);
        functor(data, size);
        buffer->Unlock();
    }
}

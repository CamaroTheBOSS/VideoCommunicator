#pragma once
#include "custom_types.h"
#include <Audioclient.h>
#include <Mmdeviceapi.h>

#include <vector>

#define REFTIMES_PER_SEC  5000000
#define REFTIMES_PER_MILLISEC  10000
namespace audio {
    class AudioSource {
    public:
        std::vector<float>& getCapturedData();
        bool setFormat(const UniqueCoTaskPtr<WAVEFORMATEX>& newFormat, bool capture);
        void reset(const size_t newSize);
        bool copyData(unsigned char* data, const UINT32 size);
        bool loadCapturedData(unsigned char* data, const UINT32 size);
        bool spaceAvailable() { return captureAudio.size() > currentCaptureCopy; }
    private:
        WAVEFORMATEXTENSIBLE capFormat{};
        WAVEFORMATEXTENSIBLE renFormat{};
        std::vector<float> captureAudio;
        size_t currentCaptureCopy = 0;
        size_t currentCaptureLoad = 0;
    };

    UniqueComPtr<IMMDeviceEnumerator> createDeviceEnumerator();
    UniqueComPtr<IMMDevice> chooseDevice(const UniqueComPtr<IMMDeviceEnumerator>& deviceEnumerator, EDataFlow flow);
    const IID IID_IAudioClient3 = __uuidof(IAudioClient3);
    UniqueCoTaskPtr<WAVEFORMATEX> getMixFormat(const UniqueComPtr<IAudioClient3>& client);
    UINT32 getBufferSize(const UniqueComPtr<IAudioClient3>& client);
    UniqueComPtr<IAudioClient3> activateDevice(const UniqueComPtr<IMMDevice>& device);
    unsigned char* allocBuffer(const UniqueComPtr<IAudioRenderClient>& renderClient, UINT32 size);
    UniqueComPtr<IAudioRenderClient> getRenderClient(const UniqueComPtr<IAudioClient3>& client);
    UniqueComPtr<IAudioCaptureClient> getCaptureClient(const UniqueComPtr<IAudioClient3>& client);
    bool initializeAudioClient(const UniqueComPtr<IAudioClient3>& client, const UniqueCoTaskPtr<WAVEFORMATEX>& mixFormat, DWORD flags = 0);
    bool initializeAudioClientForCapturing(const UniqueComPtr<IAudioClient3>& client, const UniqueCoTaskPtr<WAVEFORMATEX>& mixFormat);
    void capture(const UniqueComPtr<IAudioClient3>& capAudioClient, const UniqueComPtr<IAudioCaptureClient>& captureClient, AudioSource& capAudioSrc, const REFERENCE_TIME hnsActualDuration);
    void play(const UniqueComPtr<IAudioClient3>& renAudioClient, const UniqueComPtr<IAudioRenderClient>& renderClient, const UniqueCoTaskPtr<WAVEFORMATEX>& mixFormat, const REFERENCE_TIME hnsActualDuration, AudioSource& capAudioSrc);
    void captureAndPlay(const UniqueComPtr<IAudioClient3>& capAudioClient, const UniqueComPtr<IAudioCaptureClient>& captureClient,
        const UniqueComPtr<IAudioClient3>& renAudioClient, const UniqueComPtr<IAudioRenderClient>& renderClient, AudioSource& capAudioSrc, const REFERENCE_TIME hnsActualDuration);
}

#include "audio.h"
#include <vector>
#include <chrono>
#include <thread>

namespace audio {
    constexpr REFERENCE_TIME hnsRequestedDuration = static_cast<REFERENCE_TIME>(REFTIMES_PER_SEC);

    std::vector<float>& AudioSource::getCapturedData() {
        return captureAudio;
    }

    bool AudioSource::setFormat(const UniqueCoTaskPtr<WAVEFORMATEX>& newFormat, bool capture) {
        WAVEFORMATEXTENSIBLE format;
        if (!newFormat) {
            return false;
        }
        if (newFormat->wFormatTag == WAVE_FORMAT_EXTENSIBLE) {
            format = *reinterpret_cast<WAVEFORMATEXTENSIBLE*>(newFormat.get());
        }
        else {
            format.Format = *newFormat.get();
            format.Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
            INIT_WAVEFORMATEX_GUID(&format.SubFormat, newFormat->wFormatTag);
            format.Samples.wValidBitsPerSample = format.Format.wBitsPerSample;
            format.dwChannelMask = 0;
        }

        if (capture) {
            capFormat = format;
        }
        else {
            renFormat = format;
        }
        return true;
    }

    void AudioSource::reset(const size_t newSize) {
        captureAudio.clear();
        if (captureAudio.capacity() < newSize) {
            captureAudio.reserve(newSize);
        }
        captureAudio.resize(newSize, 0);
        currentCaptureCopy = 0;
        currentCaptureLoad = 0;
    }

    bool AudioSource::copyData(unsigned char* data, const UINT32 size) {
        float* fData = reinterpret_cast<float*>(data);
        size_t totalSamples = static_cast<size_t>(size) * capFormat.Format.nBlockAlign;
        size_t toCopy = (std::min)(static_cast<size_t>(totalSamples), captureAudio.size() - currentCaptureCopy);
        memcpy(captureAudio.data() + currentCaptureCopy, fData, toCopy);
        currentCaptureCopy += toCopy / capFormat.Format.nBlockAlign;
        if (toCopy < size) {
            return false;
        }
        return true;
    }

    bool AudioSource::loadCapturedData(unsigned char* data, const UINT32 size) {
        float* fData = reinterpret_cast<float*>(data);
        size_t totalSamples = static_cast<size_t>(size) * renFormat.Format.nChannels;
        size_t endPos = 0;
        for (size_t i = 0; i < totalSamples; i += renFormat.Format.nChannels) {
            for (size_t channel = 0; channel < renFormat.Format.nChannels; channel++) {
                fData[i + channel] = captureAudio[currentCaptureLoad];
            }
            currentCaptureLoad++;
            if (currentCaptureLoad >= captureAudio.size() || currentCaptureLoad >= currentCaptureCopy) {
                currentCaptureLoad = 0;
                endPos = i + renFormat.Format.nChannels;
                break;
            }
        }
        if (endPos > 0) {
            memcpy(fData + endPos, captureAudio.data(), totalSamples - endPos);
        }

        return currentCaptureLoad != 0;
    }

    UniqueComPtr<IMMDeviceEnumerator> createDeviceEnumerator() {
        IMMDeviceEnumerator* obj = nullptr;
        HRESULT hr = CoCreateInstance(
            __uuidof(MMDeviceEnumerator), NULL,
            CLSCTX_ALL, __uuidof(IMMDeviceEnumerator),
            reinterpret_cast<void**>(&obj)
        );
        if (!success(hr)) {
            return nullComPtr<IMMDeviceEnumerator>();
        }
        return UniqueComPtr<IMMDeviceEnumerator>(obj);
    }

    UniqueComPtr<IMMDevice> chooseDevice(const UniqueComPtr<IMMDeviceEnumerator>& deviceEnumerator, EDataFlow flow) {
        //eRender means for rendering, eCaputure means for capturing
        //eConsole means role for the device (I can choose different devices for different roles)
        IMMDevice* device = nullptr;
        HRESULT hr = deviceEnumerator->GetDefaultAudioEndpoint(flow, eConsole, &device);
        if (!success(hr)) {
            return nullComPtr<IMMDevice>();
        }
        return UniqueComPtr<IMMDevice>(device);
    }

    UniqueComPtr<IAudioClient3> activateDevice(const UniqueComPtr<IMMDevice>& device) {
        IAudioClient3* client = NULL;
        void** voidClient = reinterpret_cast<void**>(&client);
        success(device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, NULL, voidClient));
        success(device->Activate(__uuidof(IAudioClient2), CLSCTX_ALL, NULL, voidClient));
        HRESULT hr = device->Activate(__uuidof(IAudioClient3), CLSCTX_ALL, NULL, voidClient);
        if (!success(hr)) {
            return nullComPtr<IAudioClient3>();
        }
        return UniqueComPtr<IAudioClient3>(client);
    }

    UniqueCoTaskPtr<WAVEFORMATEX> getMixFormat(const UniqueComPtr<IAudioClient3>& client) {
        WAVEFORMATEX* mixFormat = nullptr;
        HRESULT hr = client->GetMixFormat(&mixFormat);
        if (!success(hr)) {
            return nullCoTaskPtr<WAVEFORMATEX>();
        }
        return UniqueCoTaskPtr<WAVEFORMATEX>(mixFormat);
    }

    UINT32 getBufferSize(const UniqueComPtr<IAudioClient3>& client) {
        UINT32 bufferSize = 0;
        HRESULT hr = client->GetBufferSize(&bufferSize);
        if (!success(hr)) {
            return 0;
        }
        return bufferSize;
    }

    unsigned char* allocBuffer(const UniqueComPtr<IAudioRenderClient>& renderClient, UINT32 size) {
        unsigned char* data = nullptr;
        HRESULT hr = renderClient->GetBuffer(size, &data);
        if (!success(hr)) {
            return 0;
        }
        return data;
    }

    UniqueComPtr<IAudioRenderClient> getRenderClient(const UniqueComPtr<IAudioClient3>& client) {
        IAudioRenderClient* renderClient = nullptr;
        HRESULT hr = client->GetService(__uuidof(IAudioRenderClient), reinterpret_cast<void**>(&renderClient));
        if (!success(hr)) {
            return nullComPtr<IAudioRenderClient>();
        }
        return UniqueComPtr<IAudioRenderClient>(renderClient);
    }

    UniqueComPtr<IAudioCaptureClient> getCaptureClient(const UniqueComPtr<IAudioClient3>& client) {
        IAudioCaptureClient* captureClient = nullptr;
        HRESULT hr = client->GetService(__uuidof(IAudioCaptureClient), reinterpret_cast<void**>(&captureClient));
        if (!success(hr)) {
            return nullComPtr<IAudioCaptureClient>();
        }
        return UniqueComPtr<IAudioCaptureClient>(captureClient);
    }

    bool initializeAudioClient(const UniqueComPtr<IAudioClient3>& client, const UniqueCoTaskPtr<WAVEFORMATEX>& mixFormat, DWORD flags) {
        HRESULT hr = client->Initialize(AUDCLNT_SHAREMODE_SHARED, flags, REFTIMES_PER_SEC, 0, mixFormat.get(), NULL);
        if (!success(hr)) {
            return false;
        }
        return true;
    }

    bool initializeAudioClientForCapturing(const UniqueComPtr<IAudioClient3>& client, const UniqueCoTaskPtr<WAVEFORMATEX>& mixFormat) {
        HRESULT hr = client->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK, 0, 0, mixFormat.get(), 0);
        if (!success(hr)) {
            return false;
        }
        return true;
    }

    void capture(const UniqueComPtr<IAudioClient3>& capAudioClient, const UniqueComPtr<IAudioCaptureClient>& captureClient, AudioSource& capAudioSrc, const REFERENCE_TIME hnsActualDuration) {
        UINT32 captureBufferSize = getBufferSize(capAudioClient);
        capAudioSrc.reset(captureBufferSize);

        unsigned char* captureData = nullptr;
        DWORD flags = 0;
        UINT32 packetLength = 0;
        
        int x = 0;
        static int iter = 0;
        auto sleepTime = std::chrono::milliseconds{ hnsActualDuration / (2 * REFTIMES_PER_MILLISEC) };
        bool spaceAvailable = true;
        auto start = std::chrono::system_clock::now();
        while (spaceAvailable) {
            std::this_thread::sleep_for(sleepTime);
            success(captureClient->GetNextPacketSize(&packetLength));
            while (packetLength > 0) {
                x++;
                UINT32 framesAvailable = 0;
                success(captureClient->GetBuffer(&captureData, &framesAvailable, &flags, NULL, NULL));
                if (flags & AUDCLNT_BUFFERFLAGS_SILENT) {
                    captureData = nullptr;
                }
                if (flags & AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY) {
                    std::cout << "Glitch detected\n";
                }

                spaceAvailable = capAudioSrc.copyData(captureData, framesAvailable);
                success(captureClient->ReleaseBuffer(framesAvailable));
                if (!spaceAvailable) {
                    break;
                }
                success(captureClient->GetNextPacketSize(&packetLength));
            }
        }

        auto end = std::chrono::system_clock::now();
        if (x > 0) {
            iter++;
            std::cout << iter << ": " << x << " - It took " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start) << "\n";
        }  
    }

    void play(const UniqueComPtr<IAudioClient3>& renAudioClient, const UniqueComPtr<IAudioRenderClient>& renderClient, const UniqueCoTaskPtr<WAVEFORMATEX>& mixFormat, const REFERENCE_TIME hnsActualDuration, AudioSource& capAudioSrc) {
        UINT32 bufferSize = getBufferSize(renAudioClient);
        unsigned char* data = allocBuffer(renderClient, bufferSize);
        bool spaceAvailable = capAudioSrc.loadCapturedData(data, bufferSize);
        renderClient->ReleaseBuffer(bufferSize, 0);
        auto sleepTime = std::chrono::milliseconds{ hnsActualDuration / (3 * REFTIMES_PER_MILLISEC) };
        auto start = std::chrono::system_clock::now();
        while (spaceAvailable) {
            std::this_thread::sleep_for(sleepTime);

            // See how much buffer space is available.
            UINT32 padding = 0;
            success(renAudioClient->GetCurrentPadding(&padding));

            UINT32 framesAvailable = bufferSize - padding;
            success(renderClient->GetBuffer(framesAvailable, &data));

            spaceAvailable = capAudioSrc.loadCapturedData(data, framesAvailable);
            success(renderClient->ReleaseBuffer(framesAvailable, 0));
        }
        auto end = std::chrono::system_clock::now();
        std::cout << "Playing took " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start) << "\n";
    }

}

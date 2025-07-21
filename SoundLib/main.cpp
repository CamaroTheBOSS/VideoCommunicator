#include <windows.h>
#include <Audioclient.h>
#include <Mmdeviceapi.h>
#include <iostream>
#include <comdef.h>

#include <memory>
#include <vector>
#include <thread>

// REFERENCE_TIME time units per second and per millisecond
#define REFTIMES_PER_SEC  5000000
#define REFTIMES_PER_MILLISEC  10000

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

bool initializeAudioClient(const UniqueComPtr<IAudioClient3>& client, const UniqueCoTaskPtr<WAVEFORMATEX>& mixFormat, DWORD flags = 0) {
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

class AudioSource {
public:
    void init() {
        if (initialized) {
            return;
        }
        pcmAudio.reserve(sampleCount);
        const float radsPerSec = static_cast<float>(2 * 3.1415926536 * frequency) / static_cast<float>(format.Format.nSamplesPerSec);
        for (unsigned long i = 0; i < sampleCount; i++) {
            pcmAudio.push_back(sin(radsPerSec * static_cast<float>(i)));
        }
        initialized = true;
        captureAudio = std::vector<float>(sampleCount);
    }

    std::vector<float>& getCapturedData() {
        return captureAudio;
    }

    void init(const std::vector<float>& otherData) {
        if (initialized) {
            return;
        }
        pcmAudio = otherData;
        initialized = true;
        captureAudio = std::vector<float>(sampleCount);
    }

    bool setFormat(const UniqueCoTaskPtr<WAVEFORMATEX>& newFormat) {
        if (!newFormat) {
            return false;
        }
        if (newFormat->wFormatTag == WAVE_FORMAT_EXTENSIBLE) {
            format = *reinterpret_cast<WAVEFORMATEXTENSIBLE*>(newFormat.get());
            return true;
        }

        format.Format = *newFormat.get();
        format.Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
        INIT_WAVEFORMATEX_GUID(&format.SubFormat, newFormat->wFormatTag);
        format.Samples.wValidBitsPerSample = format.Format.wBitsPerSample;
        format.dwChannelMask = 0;
        return true;
    }

    bool copyData(unsigned char* data, const UINT32 size) {
        float* fData = reinterpret_cast<float*>(data);
        size_t totalSamples = static_cast<size_t>(size) * format.Format.nBlockAlign;
        size_t toCopy = (std::min)(static_cast<size_t>(totalSamples), captureAudio.size() - currentCaptureCopy);
        memcpy(captureAudio.data() + currentCaptureCopy, fData, toCopy);
        currentCaptureCopy += toCopy / format.Format.nBlockAlign;
        if (toCopy < size) {
            return false;
            toCopy = size - toCopy;
            memcpy(captureAudio.data(), fData, toCopy);
            currentCaptureCopy = toCopy / format.Format.nBlockAlign;
        }
        return true;
    }

    double getCaptureFullfillmentPercentage() {
        return static_cast<double>(currentCaptureCopy) / static_cast<double>(captureAudio.size()) * 100;
    }

    bool loadCapturedData(unsigned char* data, const UINT32 size) {
        size_t toCopy = (std::min)(static_cast<size_t>(size), captureAudio.size() - currentCaptureLoad);
        memcpy(data, captureAudio.data() + currentCaptureLoad, toCopy);
        currentCaptureLoad += toCopy;
        if (toCopy < size) {
            toCopy = size - toCopy;
            memcpy(data, captureAudio.data(), toCopy);
            currentCaptureLoad = toCopy;
        }
        return true;
    }

    bool loadData(unsigned char* data, const UINT32 size) {
        float* fData = reinterpret_cast<float*>(data);
        size_t totalSamples = static_cast<size_t>(size) * format.Format.nChannels;
        size_t endPos = 0;
        for (size_t i = 0; i < totalSamples; i += format.Format.nChannels) {
            for (size_t channel = 0; channel < format.Format.nChannels; channel++) {
                fData[i + channel] = pcmAudio[current];
            }
            current++;
            if (current >= pcmAudio.size()) {
                current = 0;
                endPos = i + format.Format.nChannels;
                break;
            }
        }
        if (endPos > 0) {
            memcpy(fData + endPos, pcmAudio.data(), totalSamples - endPos);
        }

        return 0;
    }

private:
    WAVEFORMATEXTENSIBLE format{};

    bool initialized = false;
    static const unsigned int sampleCount = 96000 * 5; // I guess 5sec
    float frequency = 440;
    std::vector<float> pcmAudio;
    size_t current = 0;

    std::vector<float> captureAudio;
    size_t currentCaptureCopy = 0;
    size_t currentCaptureLoad = 0;
};

int main() {
    success(CoInitialize(nullptr));


    // 1. Choose device and initialize audio client for audio rendering
    auto deviceEnum = createDeviceEnumerator();
    auto renderDevice = chooseDevice(deviceEnum, EDataFlow::eRender);
    auto audioClient = activateDevice(renderDevice);
    auto mixFormat = getMixFormat(audioClient);
    initializeAudioClient(audioClient, mixFormat);
    auto renderClient = getRenderClient(audioClient);



    
    // CAPTURING TEST
    auto captureDevice = chooseDevice(deviceEnum, EDataFlow::eCapture);
    auto captureAudioClient = activateDevice(captureDevice);
    auto captureMixFormat = getMixFormat(captureAudioClient);
    initializeAudioClient(captureAudioClient, captureMixFormat);
    auto captureClient = getCaptureClient(captureAudioClient);
    // 4. Allocate buffer for audio capturing
    UINT32 captureBufferSize = getBufferSize(captureAudioClient);
    AudioSource captureSink{};
    captureSink.setFormat(captureMixFormat);
    captureSink.init();
    REFERENCE_TIME hnsRequestedDuration = static_cast<REFERENCE_TIME>(REFTIMES_PER_SEC);
    REFERENCE_TIME hnsActualDuration = static_cast<REFERENCE_TIME>(static_cast<float>(REFTIMES_PER_SEC) * captureBufferSize / mixFormat->nSamplesPerSec);
    
    auto sleepTime = std::chrono::milliseconds{ hnsActualDuration / (2 * REFTIMES_PER_MILLISEC) };
    unsigned char* captureData = nullptr;
    DWORD flags = 0;

    success(captureAudioClient->Start());
    UINT32 framesRecorded = 0;
    bool spaceAvailable = true;
    while (true) {
        std::this_thread::sleep_for(sleepTime);

        UINT32 packetLength = 0;
        success(captureClient->GetNextPacketSize(&packetLength));
        while (packetLength > 0) {
            UINT32 framesAvailable = 0;
            success(captureClient->GetBuffer(&captureData, &framesAvailable, &flags, NULL, NULL));
            if (flags & AUDCLNT_BUFFERFLAGS_SILENT) {
                captureData = nullptr;
            }
            if (flags & AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY) {
                std::cout << "Glitch detected\n";
            }
            framesRecorded += framesAvailable;
            spaceAvailable = captureSink.copyData(captureData, framesAvailable);
            success(captureClient->ReleaseBuffer(framesAvailable));
            if (!spaceAvailable) {
                break;
            }
            success(captureClient->GetNextPacketSize(&packetLength));   
        }
        std::cout << "Fullfilment: " << captureSink.getCaptureFullfillmentPercentage() << "%\n";
        std::cout << "Recorded: " << framesRecorded << '\n';
        if (!spaceAvailable) {
            break;
        }
    }

    //// 2. Allocate buffer for audio rendering
    UINT32 bufferSize = getBufferSize(audioClient);
    unsigned char* data = allocBuffer(renderClient, bufferSize);

    AudioSource audio{};
    audio.setFormat(mixFormat);
    audio.init(captureSink.getCapturedData());
    audio.loadData(data, bufferSize);
    renderClient->ReleaseBuffer(bufferSize, 0);

    hnsRequestedDuration = static_cast<REFERENCE_TIME>(REFTIMES_PER_SEC);
    hnsActualDuration = static_cast<REFERENCE_TIME>(static_cast<float>(REFTIMES_PER_SEC) * bufferSize / mixFormat->nSamplesPerSec);

    success(audioClient->Start());
    sleepTime = std::chrono::milliseconds{ hnsActualDuration / (3 * REFTIMES_PER_MILLISEC) };
    while (true) {
        std::this_thread::sleep_for(sleepTime);

        // See how much buffer space is available.
        UINT32 padding = 0;
        success(audioClient->GetCurrentPadding(&padding));

        UINT32 framesAvailable = bufferSize - padding;
        success(renderClient->GetBuffer(framesAvailable, &data));

        // Get next 1/2-second of data from the audio source.
        audio.loadData(data, framesAvailable);
        success(renderClient->ReleaseBuffer(framesAvailable, 0));
        std::cout << "FramesAvailable: " << framesAvailable << '\n';

    }

    // Wait for last data in buffer to play before stopping.
    std::this_thread::sleep_for(sleepTime);
    success(audioClient->Stop());  // Stop playing.
    return 0;
}
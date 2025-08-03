#include <iostream>
#define WIN32_LEAN_AND_MEAN
#include "mfmediaengine.h"
#include "mfapi.h"
#include "mfreadwrite.h"

#include "custom_types.h"

#include <Dbt.h>
#include "video.h"
#include "audio.h"
#include "network.h"

#pragma comment (lib, "ole32.lib")
#pragma comment (lib, "mf.lib")
#pragma comment (lib, "mfplat.lib")
#pragma comment (lib, "mfuuid.lib")
#pragma comment (lib, "mfreadwrite.lib")
#pragma comment (lib, "Ws2_32.lib")

#include <locale>
#include <locale.h>

#ifndef MS_STDLIB_BUGS
#  if ( _MSC_VER || __MINGW32__ || __MSVCRT__ )
#    define MS_STDLIB_BUGS 1
#  else
#    define MS_STDLIB_BUGS 0
#  endif
#endif

#if MS_STDLIB_BUGS
#  include <io.h>
#  include <fcntl.h>
#endif

static void initLocale(void) {
#if MS_STDLIB_BUGS
    constexpr char cp_utf16le[] = ".1200";
    setlocale(LC_ALL, cp_utf16le);
    int result = _setmode(_fileno(stdout), _O_WTEXT);
#else
    // The correct locale name may vary by OS, e.g., "en_US.utf8".
    constexpr char locale_name[] = "";
    setlocale(LC_ALL, locale_name);
    std::locale::global(std::locale(locale_name));
    std::wcin.imbue(std::locale())
        std::wcout.imbue(std::locale());
#endif
}

int main()
{
    WSADATA wsaData;
    WORD mVersionRequested = MAKEWORD(2, 2);
    int wsaError = WSAStartup(mVersionRequested, &wsaData);
    if (wsaError) {
        std::cout << wsaError << " Error on WSA stratup\n";
        WSACleanup();
        return -1;
    }

    net::ConnectionSettings settings{
        .ip = "127.0.0.1",
        .port = 8888
    };
    net::UDPConnection connection{ settings };
    








    initLocale();
    success(CoInitialize(nullptr));

    // VIDEO INIT
    auto attributes = video::createAttributes();
    success(attributes->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE, MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID));
    auto devices = video::createDeviceEnum(attributes);
    auto mediaSource = video::createMediaSource(devices[0]);
   /* auto reader = video::createSourceReader(mediaSource);
    auto currentType = video::getCurrentMediaType(reader);
    auto frameSize = video::getFrameSize(currentType);
    auto format = video::getMediaFormat(currentType);*/

    // AUDIO INIT
    success(attributes->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE, MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_AUDCAP_GUID));
    auto audioDevices = video::createDeviceEnum(attributes);
    auto audioCapMediaSource = video::createMediaSource(audioDevices[0]);
    //auto audioReader = video::createSourceReader(audioCapMediaSource);

    auto audioSink = video::createEmptyMediaSink();
    auto streamSink = video::getStreamSinkByIndex(0, audioSink);
    auto typeHandler = video::getMediaTypeHandler(streamSink);
    auto mediaType = UniqueComPtr<IMFMediaType>();
    DWORD deviceCount = 0;
    success(typeHandler->GetMediaTypeCount(&deviceCount));
    for (int i = 0; i < deviceCount; i++) {
        auto tmpMediaType = video::getMediaTypeByIndex(i, typeHandler);
        if (typeHandler->IsMediaTypeSupported(tmpMediaType.get(), nullptr) == S_OK) {
            mediaType = std::move(tmpMediaType);
            break;
        }
    }
    success(typeHandler->SetCurrentMediaType(mediaType.get()));
    //success(audioReader->SetCurrentMediaType(0, nullptr, mediaType.get()));
    auto sinkWriter = video::createSourceWriter(audioSink);
    success(sinkWriter->SetInputMediaType(0, mediaType.get(), nullptr));

    // AGGREGATE CAPTURE INIT
    auto mediaSourceCollection = video::createEmptyCollection();
    success(mediaSourceCollection->AddElement(mediaSource.get()));
    success(mediaSourceCollection->AddElement(audioCapMediaSource.get()));
    auto aggregateMediaSource = video::createAggregateMediaSource(mediaSourceCollection);
    auto aggregateReader = video::createSourceReader(aggregateMediaSource);
    auto currentType = video::getCurrentMediaType(aggregateReader);
    auto frameSize = video::getFrameSize(currentType);
    auto format = video::getMediaFormat(currentType);
    success(aggregateReader->SetCurrentMediaType(MF_SOURCE_READER_FIRST_AUDIO_STREAM, nullptr, mediaType.get()));

    connection.connectServer();
    // AGGREGATE CAPTURE LOOP
    success(sinkWriter->BeginWriting());
    while (true) {
        auto audioSample = video::readAudioSampleBlockingMode(aggregateReader);
        auto videoSample = video::readSampleBlockingMode(aggregateReader);
        /*auto buffer = video::getContignousBuffer(videoSample);
        std::vector<unsigned char> rgb24(frameSize.width * frameSize.height * 24);
        video::runOnBufferData(buffer, [&](BYTE* data, DWORD size) {
            rgb24 = video::convertYUY2ToRGB24(data, size);
            }
        );*/
        //video::writeToBitmap(rgb24, frameSize);
        success(sinkWriter->WriteSample(0, audioSample.sample.get()));

        auto buffer = video::getContignousBuffer(audioSample.sample);
        video::runOnBufferData(buffer, [&](BYTE* data, DWORD size) {
            connection.sendData(data, size);
        });;

        buffer = video::getContignousBuffer(videoSample.sample);
        video::runOnBufferData(buffer, [&](BYTE* data, DWORD size) {
            connection.sendData(data, size);
            });;
    }
    success(sinkWriter->Finalize());
    success(audioSink->Shutdown());



    // AUDIO CAPTURE LOOP
    /*success(sinkWriter->BeginWriting());
    while (true) {
        auto audioSample = video::readAudioSampleBlockingMode(audioReader);
        success(sinkWriter->WriteSample(0, audioSample.get()));
    }
    success(sinkWriter->Finalize());
    success(audioSink->Shutdown());*/
    
    


    // AUDIO INIT WASAPI
    /*auto deviceEnum = audio::createDeviceEnumerator();
    auto audioDevice = audio::chooseDevice(deviceEnum, EDataFlow::eRender);
    auto audioClient = audio::activateDevice(audioDevice);
    auto mixFormat = audio::getMixFormat(audioClient);
    audio::initializeAudioClient(audioClient, mixFormat);
    auto renderClient = audio::getRenderClient(audioClient);
    success(audioClient->Start());

    auto capAudioDevice = audio::chooseDevice(deviceEnum, EDataFlow::eCapture);
    auto capAudioClient = audio::activateDevice(capAudioDevice);
    auto capMixFormat = audio::getMixFormat(capAudioClient);
    audio::initializeAudioClient(capAudioClient, capMixFormat);
    auto captureClient = audio::getCaptureClient(capAudioClient);
    success(capAudioClient->Start());
    
    audio::AudioSource capAudioSrc;
    capAudioSrc.setFormat(capMixFormat, true);
    capAudioSrc.setFormat(mixFormat, false);

    REFERENCE_TIME hnsRequestedDuration = static_cast<REFERENCE_TIME>(REFTIMES_PER_SEC);
    REFERENCE_TIME captureHnsActualDuration = static_cast<REFERENCE_TIME>(static_cast<float>(REFTIMES_PER_SEC) / mixFormat->nSamplesPerSec);
    REFERENCE_TIME renderHnsActualDuration = static_cast<REFERENCE_TIME>(static_cast<float>(REFTIMES_PER_SEC) * 24000 / mixFormat->nSamplesPerSec);
    audio::captureAndPlay(capAudioClient, captureClient, audioClient, renderClient, capAudioSrc, captureHnsActualDuration);
    while (true) {
        audio::capture(capAudioClient, captureClient, capAudioSrc, captureHnsActualDuration);
        audio::play(audioClient, renderClient, mixFormat, renderHnsActualDuration, capAudioSrc);
    }*/

    // VIDEO CAPTURE LOOP
    /*auto sample = video::readSampleBlockingMode(reader);
    auto buffer = video::getContignousBuffer(sample);
    std::vector<unsigned char> rgb24(frameSize.width * frameSize.height * 24);
    video::runOnBufferData(buffer, [&](BYTE* data, DWORD size) {
            rgb24 = video::convertYUY2ToRGB24(data, size);
        }
    );
    video::writeToBitmap(rgb24, frameSize);*/
    WSACleanup();
}

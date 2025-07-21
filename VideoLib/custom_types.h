#pragma once

#include "mfmediaengine.h"
#include "mfapi.h"
#include "mfreadwrite.h"

#include <comdef.h>
#include <iostream>

static bool success(HRESULT result) {
    if (SUCCEEDED(result)) {
        return true;
    }
    _com_error err(result);
    LPCTSTR errMsg = err.ErrorMessage();
    std::wcout << errMsg << '\n';
    return false;
}

struct FrameSize {
    int width = 0;
    int height = 0;
};

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

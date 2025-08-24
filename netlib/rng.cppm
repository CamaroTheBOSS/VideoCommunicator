module;

export module rng;
import std;

namespace rng {
	static auto rng_init(const unsigned int seed = 0) {
		if (seed != 0) {
			return std::mt19937(seed);
		}
		std::random_device device;
		std::random_device::result_type data[(std::mt19937::state_size - 1) / sizeof(device()) + 1];
		std::generate(std::begin(data), std::end(data), std::ref(device));
		std::seed_seq seed_seq{ std::begin(data), std::end(data) };
		return std::mt19937(seed_seq);
	}
	static auto rng_engine = rng_init(-1);

	export template<std::integral T>
	T draw_random(const T min, const T max) {
		auto dist = std::uniform_int_distribution<T>(min, max);
		return dist(rng_engine);
	}
}
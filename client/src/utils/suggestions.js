// Lightweight rule engine for weather suggestions (MVP)
// Input shape: { current, forecast }
const RAIN_TYPES = ['Rain', 'Drizzle', 'Thunderstorm'];

function _isRainyItem(item) {
  if (!item) return false;

  console.log('Kiểm tra item:', item);

  // Kiểm tra weather.main
  if (item.weather?.main && RAIN_TYPES.includes(item.weather.main)) {
    console.log('  -> Có mưa từ weather.main:', item.weather.main);
    return true;
  }

  // Kiểm tra weather array
  if (Array.isArray(item.weather) && item.weather.length > 0) {
    const main = item.weather[0].main;
    if (main && RAIN_TYPES.includes(main)) {
      console.log('  -> Có mưa từ weather[0].main:', main);
      return true;
    }
  }

  // Probability of precipitation (pop) if available
  if (typeof item.pop === 'number' && item.pop >= 0.3) {
    console.log('  -> Có mưa từ pop:', item.pop);
    return true;
  }

  // Rain volume fields
  if (item.rain) {
    // could be object like { '1h': 2, '3h': 5 }
    if (typeof item.rain === 'object') {
      const keys = Object.keys(item.rain);
      for (const k of keys) {
        if (Number(item.rain[k]) > 0) {
          console.log('  -> Có mưa từ rain object:', item.rain);
          return true;
        }
      }
    }
    if (Number(item.rain) > 0) {
      console.log('  -> Có mưa từ rain number:', item.rain);
      return true;
    }
  }

  return false;
}

export function getSuggestions({ current, forecast }) {
  console.log('=== getSuggestions BẮT ĐẦU ===');
  console.log('Input - current:', current);
  console.log('Input - forecast:', forecast);
  
  const suggestions = [];

  // Umbrella rule: if any upcoming hourly forecast in next 6 entries indicates rain
  try {
    let hourly = [];

    if (Array.isArray(forecast?.hourly) && forecast.hourly.length) {
      hourly = forecast.hourly;
      console.log('Dùng forecast.hourly, length:', hourly.length);
    } else if (Array.isArray(forecast?.list) && forecast.list.length) {
      hourly = forecast.list;
      console.log('Dùng forecast.list, length:', hourly.length);
    } else if (Array.isArray(forecast?.daily) && forecast.daily.length) {
      hourly = forecast.daily;
      console.log('Dùng forecast.daily, length:', hourly.length);
    }

    console.log('Hourly data:', hourly);

    const nextItems = hourly.slice(0, 6);
    console.log('Kiểm tra 6 items đầu:', nextItems);

    const rainy = nextItems.some(_isRainyItem);
    console.log('Có mưa?', rainy);

    if (rainy) {
      const rainyCount = nextItems.filter(_isRainyItem).length;
      const level = rainyCount >= 3 ? 'warning' : 'info';

      console.log('Tạo suggestion với level:', level);

      suggestions.push({
        id: 'umbrella_01',
        type: 'precipitation',
        level,
        title: 'Mang ô',
        message: 'Có khả năng mưa trong vài giờ tới — nhớ mang ô/áo mưa.',
        icon: 'rain',
        expiresAt: Date.now() + 1000 * 60 * 60 // 1 hour
      });
    } else {
      console.log('Không phát hiện mưa trong forecast');
    }

    // THÊM: Kiểm tra thời tiết hiện tại
    if (current?.weather?.main && RAIN_TYPES.includes(current.weather.main)) {
      console.log('Hiện tại đang mưa!');
      if (suggestions.length === 0) {
        suggestions.push({
          id: 'umbrella_02',
          type: 'precipitation',
          level: 'warning',
          title: 'Đang mưa',
          message: 'Hiện tại trời đang mưa — nhớ mang ô/áo mưa.',
          icon: 'rain',
          expiresAt: Date.now() + 1000 * 60 * 60
        });
      }
    }

    // THÊM: Suggestion mẫu để test (tạm thời)
    if (suggestions.length === 0) {
      console.log('Không có suggestion nào, tạo suggestion test');
      suggestions.push({
        id: 'test_01',
        type: 'info',
        level: 'info',
        title: 'Thời tiết đẹp',
        message: 'Thời tiết hiện tại khá tốt, hãy tận hưởng ngày mới!',
        icon: 'sun',
        expiresAt: Date.now() + 1000 * 60 * 60
      });
    }

  } catch (e) {
    console.error('Lỗi khi tạo suggestion:', e);
  }

  console.log('Suggestions cuối cùng:', suggestions);
  console.log('=== getSuggestions KẾT THÚC ===');
  return suggestions;
}

export default { getSuggestions };
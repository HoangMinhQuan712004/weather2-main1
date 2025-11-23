const { GoogleGenerativeAI } = require("@google/generative-ai");
const fs = require("fs");
const path = require("path");
const User = require("../models/User");

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });

const prompt_text = `
Bạn là một trợ lý AI chuyên về trích xuất thông tin. Phân tích hình ảnh CCCD Việt Nam này.
Chỉ trích xuất các thông tin sau và trả về dưới dạng JSON:
* \`so_cccd\` (Số CCCD)
* \`ho_va_ten\` (Họ và tên)
* \`ngay_sinh\` (Ngày sinh, DD/MM/YYYY)
* \`gioi_tinh\` (Giới tính)
* \`quoc_tich\` (Quốc tịch)
* \`que_quan\` (Quê quán)
* \`noi_thuong_tru\` (Nơi thường trú)
* \`ngay_het_han\` (Ngày hết hạn)
Chỉ trả về duy nhất đối tượng JSON, không giải thích, không markdown.
`;

function fileToGenerativePart(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Không tìm thấy file ảnh: ${filePath}`);
  }
  const fileData = fs.readFileSync(filePath);
  return {
    inlineData: {
      data: fileData.toString("base64"),
      // detect mime type from extension so we send the correct type
      mimeType: (() => {
        const ext = path.extname(filePath || '').toLowerCase();
        if (ext === '.png') return 'image/png';
        if (ext === '.webp') return 'image/webp';
        if (ext === '.gif') return 'image/gif';
        return 'image/jpeg';
      })(),
    },
  };
}

async function extractCccdInfo(imagePath) {
  try {
    const imagePart = fileToGenerativePart(imagePath);
    const result = await model.generateContent([prompt_text, imagePart]);
    const response = result.response;
    let text = response.text();

    // Try to extract JSON inside ```json code blocks first
    const codeBlockMatch = text.match(/```json\s*([\s\S]*?)\s*```/i);
    if (codeBlockMatch && codeBlockMatch[1]) {
      text = codeBlockMatch[1].trim();
    } else {
      // Fallback: extract first {...} object in the text
      const braceStart = text.indexOf('{');
      const braceEnd = text.lastIndexOf('}');
      if (braceStart !== -1 && braceEnd !== -1 && braceEnd > braceStart) {
        text = text.substring(braceStart, braceEnd + 1);
      }
    }

    // Clean common issues: trailing commas, smart quotes
    text = text.replace(/[“”]/g, '"').replace(/[‘’]/g, "'");
    text = text.replace(/,\s*}/g, '}').replace(/,\s*]/g, ']');

    // Ensure keys are quoted (simple heuristic) if model returned unquoted keys
    // This is conservative: only run if it looks like object but keys aren't quoted
    if (/\{\s*[^\"]+?:/.test(text)) {
      text = text.replace(/([\{,\s])(\w+)\s*:/g, '$1"$2":');
    }

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      console.error('Không thể parse JSON từ response OCR. Raw text:', text);
      throw new Error('Không thể trích xuất thông tin từ ảnh CCCD');
    }

    // Normalize some fields
    if (parsed.so_cccd) {
      parsed.so_cccd = String(parsed.so_cccd).replace(/\D/g, '');
    }

    if (parsed.ngay_sinh) {
      // Normalize various date formats to DD/MM/YYYY
      const d = String(parsed.ngay_sinh).trim();
      const m = d.match(/(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2,4})/);
      if (m) {
        let day = m[1].padStart(2, '0');
        let month = m[2].padStart(2, '0');
        let year = m[3];
        if (year.length === 2) {
          const yNum = parseInt(year, 10);
          year = (yNum > 30 ? '19' : '20') + year;
        }
        parsed.ngay_sinh = `${day}/${month}/${year}`;
      }
    }

    return parsed;
  } catch (error) {
    console.error("Lỗi khi xử lý ảnh CCCD:", error);
    throw new Error("Không thể trích xuất thông tin từ ảnh CCCD");
  }
}

exports.registerWithCCCD = async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Vui lòng tải lên ảnh CCCD' });
  }

  try {
    const cccdInfo = await extractCccdInfo(req.file.path);

    // Check whether CCCD already exists in system
    const existingUser = await User.findOne({ cccd: cccdInfo.so_cccd });

    // Remove uploaded temporary file
    try {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    } catch (e) {
      console.warn('Không xóa được file tạm:', e.message);
    }

    // Return extracted info to client for confirmation (do not create account here)
    return res.json({
      success: true,
      extracted: cccdInfo,
      exists: Boolean(existingUser)
    });
  } catch (error) {
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: error.message || 'Lỗi khi đăng ký CCCD' });
  }
};

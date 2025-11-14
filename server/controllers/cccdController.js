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
      mimeType: "image/jpeg",
    },
  };
}

async function extractCccdInfo(imagePath) {
  try {
    const imagePart = fileToGenerativePart(imagePath);
    const result = await model.generateContent([prompt_text, imagePart]);
    const response = result.response;
    let text = response.text();
    text = text.replace(/```json\n?(.*?)\n?```/s, "$1").trim();
    return JSON.parse(text);
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
    // Trích xuất thông tin từ ảnh CCCD
    const cccdInfo = await extractCccdInfo(req.file.path);
    
    // Kiểm tra xem CCCD đã tồn tại chưa
    const existingUser = await User.findOne({ cccd: cccdInfo.so_cccd });
    if (existingUser) {
      throw new Error('Số CCCD đã được đăng ký');
    }

    // Tạo tài khoản mới
    const newUser = new User({
      name: cccdInfo.ho_va_ten,
      cccd: cccdInfo.so_cccd,
      dateOfBirth: cccdInfo.ngay_sinh,
      gender: cccdInfo.gioi_tinh,
      address: cccdInfo.noi_thuong_tru,
      // Thêm các trường khác nếu cần
    });

    await newUser.save();

    // Xóa file tạm sau khi xử lý
    fs.unlinkSync(req.file.path);

    res.json({
      success: true,
      message: 'Đăng ký thành công',
      user: {
        id: newUser._id,
        name: newUser.name,
        cccd: newUser.cccd
      }
    });
  } catch (error) {
    // Xóa file tạm nếu có lỗi
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ 
      error: error.message || 'Đã xảy ra lỗi khi xử lý đăng ký' 
    });
  }
};
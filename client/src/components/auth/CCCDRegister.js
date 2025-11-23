import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import styled from 'styled-components';
import { FiUpload, FiArrowLeft, FiCreditCard, FiUser, FiCalendar, FiMapPin, FiCheck } from 'react-icons/fi';
import { toast } from 'react-toastify';

const Container = styled.div`
  max-width: 600px;
  margin: 2rem auto;
  padding: 2rem;
  background: rgba(255, 255, 255, 0.08);
  border-radius: 15px;
  backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.1);
`;

const Title = styled.h2`
  text-align: center;
  color: #fff;
  margin-bottom: 2rem;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
`;

const BackButton = styled.button`
  background: none;
  border: none;
  color: #4fc3f7;
  display: flex;
  align-items: center;
  gap: 5px;
  margin-bottom: 1rem;
  cursor: pointer;
  font-size: 0.95rem;
  
  &:hover {
    text-decoration: underline;
  }
`;

const UploadArea = styled.label`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 2rem;
  border: 2px dashed rgba(255, 255, 255, 0.3);
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.3s ease;
  margin-bottom: 1.5rem;
  text-align: center;
  min-height: 200px;

  &:hover {
    border-color: #4fc3f7;
    background: rgba(79, 195, 247, 0.1);
  }

  input[type="file"] {
    display: none;
  }
`;

const UploadIcon = styled.div`
  font-size: 3rem;
  color: #4fc3f7;
  margin-bottom: 1rem;
`;

const PreviewImage = styled.img`
  max-width: 100%;
  max-height: 300px;
  border-radius: 8px;
  margin: 1rem 0;
  border: 1px solid rgba(255, 255, 255, 0.1);
`;

const Button = styled.button`
  width: 100%;
  padding: 12px;
  background: linear-gradient(45deg, #2196f3, #1976d2);
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  transition: all 0.3s ease;
  margin-top: 1rem;

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(33, 150, 243, 0.3);
  }

  &:disabled {
    opacity: 0.7;
    cursor: not-allowed;
    background: #666;
  }
`;

const FormGroup = styled.div`
  margin-bottom: 1.5rem;
`;

const Label = styled.label`
  display: block;
  margin-bottom: 0.5rem;
  color: #e0e0e0;
  font-size: 0.95rem;
  display: flex;
  align-items: center;
  gap: 8px;
`;

const Input = styled.input`
  width: 100%;
  padding: 12px 15px;
  background: rgba(255, 255, 255, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 8px;
  color: #fff;
  font-size: 1rem;
  transition: all 0.3s ease;

  &:focus {
    outline: none;
    border-color: #4fc3f7;
    box-shadow: 0 0 0 2px rgba(79, 195, 247, 0.2);
  }

  &:disabled {
    background: rgba(255, 255, 255, 0.05);
    cursor: not-allowed;
  }
`;

const CCCDRegister = () => {
  const [step, setStep] = useState(1);
  const [selectedFile, setSelectedFile] = useState(null);
  const [preview, setPreview] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    name: '',
    cccd: '',
    dateOfBirth: '',
    gender: '',
    address: ''
  });
  const navigate = useNavigate();

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setSelectedFile(file);
      const reader = new FileReader();
      reader.onloadend = () => {
        setPreview(reader.result);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleExtractInfo = async () => {
    if (!selectedFile) {
      toast.error('Vui lòng chọn ảnh CCCD');
      return;
    }

    const formData = new FormData();
    formData.append('cccdImage', selectedFile);

    try {
      setIsLoading(true);
      const response = await fetch('/api/cccd/register', {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Đã xảy ra lỗi khi xử lý ảnh');
      }

      // Received extracted data from server. Navigate to Register page
      // and pass extracted info as prefill state for the registration form.
      const extracted = data.extracted || {};
      const exists = data.exists || false;
      navigate('/register', { state: { prefill: extracted, exists } });
    } catch (error) {
      console.error('Lỗi khi trích xuất thông tin:', error);
      toast.error(error.message || 'Có lỗi xảy ra khi xử lý ảnh CCCD');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (formData.password !== formData.confirmPassword) {
      toast.error('Mật khẩu xác nhận không khớp');
      return;
    }

    try {
      setIsLoading(true);
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Đăng ký thất bại');
      }

      toast.success('Đăng ký thành công! Vui lòng đăng nhập.');
      navigate('/login');
    } catch (error) {
      console.error('Lỗi khi đăng ký:', error);
      toast.error(error.message || 'Có lỗi xảy ra khi đăng ký');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Container>
      <BackButton onClick={() => step === 1 ? navigate(-1) : setStep(1)}>
        <FiArrowLeft /> {step === 1 ? 'Quay lại' : 'Quay lại bước trước'}
      </BackButton>
      
      <Title>
        <FiCreditCard size={28} />
        {step === 1 ? 'Xác thực CCCD' : 'Hoàn tất đăng ký'}
      </Title>

      {step === 1 ? (
        <>
          <UploadArea>
            <input
              type="file"
              accept="image/*"
              capture="environment"
              onChange={handleFileChange}
              disabled={isLoading}
            />
            {preview ? (
              <PreviewImage src={preview} alt="CCCD Preview" />
            ) : (
              <>
                <UploadIcon>
                  <FiUpload />
                </UploadIcon>
                <p>Nhấn để tải lên ảnh CCCD</p>
                <p style={{ fontSize: '0.9rem', opacity: 0.8 }}>
                  Hoặc kéo thả ảnh vào đây
                </p>
              </>
            )}
          </UploadArea>
          
          <Button 
            onClick={handleExtractInfo} 
            disabled={!selectedFile || isLoading}
          >
            {isLoading ? 'Đang xử lý...' : 'Tiếp tục'}
          </Button>
        </>
      ) : (
        <form onSubmit={handleSubmit}>
          <FormGroup>
            <Label><FiUser /> Họ và tên</Label>
            <Input
              type="text"
              name="name"
              value={formData.name}
              onChange={handleInputChange}
              required
              placeholder="Nhập họ và tên"
            />
          </FormGroup>

          <FormGroup>
            <Label><FiCreditCard /> Số CCCD</Label>
            <Input
              type="text"
              name="cccd"
              value={formData.cccd}
              onChange={handleInputChange}
              required
              placeholder="Nhập số CCCD"
              disabled
            />
          </FormGroup>

          <FormGroup>
            <Label><FiCalendar /> Ngày sinh</Label>
            <Input
              type="date"
              name="dateOfBirth"
              value={formData.dateOfBirth}
              onChange={handleInputChange}
              required
            />
          </FormGroup>

          <FormGroup>
            <Label>Giới tính</Label>
            <div style={{ display: 'flex', gap: '1rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                <input
                  type="radio"
                  name="gender"
                  value="Nam"
                  checked={formData.gender === 'Nam'}
                  onChange={handleInputChange}
                  required
                />
                Nam
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                <input
                  type="radio"
                  name="gender"
                  value="Nữ"
                  checked={formData.gender === 'Nữ'}
                  onChange={handleInputChange}
                />
                Nữ
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                <input
                  type="radio"
                  name="gender"
                  value="Khác"
                  checked={formData.gender === 'Khác'}
                  onChange={handleInputChange}
                />
                Khác
              </label>
            </div>
          </FormGroup>

          <FormGroup>
            <Label><FiMapPin /> Địa chỉ</Label>
            <Input
              type="text"
              name="address"
              value={formData.address}
              onChange={handleInputChange}
              required
              placeholder="Nhập địa chỉ"
            />
          </FormGroup>

          <FormGroup>
            <Label>Email</Label>
            <Input
              type="email"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              required
              placeholder="Nhập email"
            />
          </FormGroup>

          <FormGroup>
            <Label>Mật khẩu</Label>
            <Input
              type="password"
              name="password"
              value={formData.password}
              onChange={handleInputChange}
              required
              minLength="6"
              placeholder="Nhập mật khẩu (tối thiểu 6 ký tự)"
            />
          </FormGroup>

          <FormGroup>
            <Label>Xác nhận mật khẩu</Label>
            <Input
              type="password"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleInputChange}
              required
              placeholder="Nhập lại mật khẩu"
            />
          </FormGroup>

          <Button type="submit" disabled={isLoading}>
            {isLoading ? 'Đang xử lý...' : 'Hoàn tất đăng ký'}
          </Button>
        </form>
      )}
    </Container>
  );
};

export default CCCDRegister;
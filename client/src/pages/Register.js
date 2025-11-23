import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import styled from 'styled-components';
import { FiEye, FiEyeOff, FiMail, FiLock, FiUser, FiCreditCard, FiCalendar } from 'react-icons/fi';

const RegisterContainer = styled.div`
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 20px;
`;

const RegisterCard = styled.div`
  background: rgba(255, 255, 255, 0.1);
  backdrop-filter: blur(10px);
  border-radius: 20px;
  padding: 40px;
  width: 100%;
  max-width: 450px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.2);
`;

const Logo = styled.div`
  text-align: center;
  margin-bottom: 30px;
  
  h1 {
    font-size: 3rem;
    font-weight: bold;
    color: white;
    margin: 0;
    text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
  }
  
  p {
    color: rgba(255, 255, 255, 0.9);
    margin-top: 10px;
    font-size: 1.1rem;
  }
`;

const Form = styled.form`
  display: flex;
  flex-direction: column;
  gap: 20px;
`;

const InputGroup = styled.div`
  position: relative;
  display: flex;
  align-items: center;
`;

const InputIcon = styled.div`
  position: absolute;
  left: 15px;
  color: rgba(255, 255, 255, 0.7);
  font-size: 20px;
  pointer-events: none;
  z-index: 1;
`;

const Input = styled.input`
  width: 100%;
  padding: 15px 15px 15px 50px;
  background: rgba(255, 255, 255, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.3);
  border-radius: 10px;
  color: white;
  font-size: 16px;
  transition: all 0.3s ease;

  &::placeholder {
    color: rgba(255, 255, 255, 0.6);
  }

  &:focus {
    outline: none;
    background: rgba(255, 255, 255, 0.15);
    border-color: rgba(255, 255, 255, 0.5);
  }
`;

const PasswordToggle = styled.button`
  position: absolute;
  right: 15px;
  background: none;
  border: none;
  color: rgba(255, 255, 255, 0.7);
  cursor: pointer;
  font-size: 20px;
  transition: color 0.3s ease;

  &:hover {
    color: white;
  }
`;

const Button = styled.button`
  width: 100%;
  padding: 15px;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  border: none;
  border-radius: 10px;
  color: white;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s ease;
  margin-top: 10px;

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 5px 20px rgba(0, 0, 0, 0.2);
  }

  &:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
  }
`;

const ErrorMessage = styled.div`
  background: rgba(255, 59, 48, 0.2);
  border: 1px solid rgba(255, 59, 48, 0.5);
  color: white;
  padding: 12px;
  border-radius: 10px;
  margin-bottom: 20px;
  text-align: center;
  font-size: 14px;
`;

const LinkText = styled.p`
  text-align: center;
  color: rgba(255, 255, 255, 0.8);
  margin-top: 20px;
  
  a {
    color: white;
    text-decoration: none;
    font-weight: 600;
    
    &:hover {
      text-decoration: underline;
    }
  }
`;

const Divider = styled.div`
  display: flex;
  align-items: center;
  margin: 1.5rem 0;
  color: rgba(255, 255, 255, 0.7);
  font-size: 0.9rem;
  
  &::before,
  &::after {
    content: '';
    flex: 1;
    height: 1px;
    background: rgba(255, 255, 255, 0.3);
    margin: 0 10px;
  }
`;

const CCCDButton = styled.button`
  width: 100%;
  padding: 15px;
  background: transparent;
  border: 1px solid rgba(255, 255, 255, 0.3);
  border-radius: 10px;
  color: white;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s ease;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  margin-top: 10px;

  &:hover {
    background: rgba(255, 255, 255, 0.1);
    transform: translateY(-2px);
  }

  &:disabled {
    opacity: 0.6;
    cursor: not-allowed;
    transform: none;
  }
`;

const Register = () => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const location = useLocation();
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState('');
  const [cccdExists, setCccdExists] = useState(false);
  const [isCCCD, setIsCCCD] = useState(false);
  
  const { register, loading } = useAuth();
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
    setError('');
  };

  useEffect(() => {
    // If navigated with prefill from CCCD scan, populate fields and switch to CCCD flow
    const prefill = location.state && location.state.prefill;
    const existsFlag = location.state && location.state.exists;
    if (existsFlag) setCccdExists(true);
    if (prefill) {
      setIsCCCD(true);
      setFormData(prev => ({
        ...prev,
        // keep username/email empty for user to fill, but set cccd-related fields
        cccd: prefill.so_cccd || '',
        fullName: prefill.ho_va_ten || prefill.ho_ten || '',
        dateOfBirth: prefill.ngay_sinh ? (() => {
          // convert DD/MM/YYYY -> YYYY-MM-DD for <input type=date>
          const m = prefill.ngay_sinh.match(/(\d{1,2})\/(\d{1,2})\/(\d{4})/);
          if (m) return `${m[3]}-${m[2].padStart(2,'0')}-${m[1].padStart(2,'0')}`;
          return '';
        })() : '',
        gender: prefill.gioi_tinh || '',
        address: prefill.noi_thuong_tru || ''
      }));
    }
  }, [location]);

  const validateForm = () => {
    // Separate validation for CCCD vs normal registration
    if (isCCCD) {
      // CCCD flow validation
      if (!formData.fullName || !formData.cccd || !formData.dateOfBirth || !formData.gender || !formData.address || !formData.email || !formData.password || !formData.confirmPassword) {
        setError('Vui lòng điền đầy đủ thông tin');
        return false;
      }
    } else {
      // Normal registration flow validation
      if (!formData.username || !formData.email || !formData.password || !formData.confirmPassword) {
        setError('Vui lòng điền đầy đủ thông tin');
        return false;
      }
    }

    if (formData.password !== formData.confirmPassword) {
      setError('Mật khẩu xác nhận không khớp');
      return false;
    }

    if (formData.password.length < 6) {
      setError('Mật khẩu phải có ít nhất 6 ký tự');
      return false;
    }

    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!validateForm()) return;

    const result = await register(
      formData.username, 
      formData.email, 
      formData.password,
      isCCCD ? {
        cccd: formData.cccd,
        fullName: formData.fullName,
        dateOfBirth: formData.dateOfBirth,
        gender: formData.gender,
        address: formData.address
      } : null
    );

    if (!result.success) {
      console.error('Register failed response:', result);
      setError(result.message || 'Đăng ký thất bại. Vui lòng thử lại.');
    }
  };

  const handleCCCDRegister = () => {
    navigate('/register/cccd');
  };

  return (
    <RegisterContainer>
      <RegisterCard>
        <Logo>
          <h1>WW</h1>
          <p>{isCCCD ? 'Đăng ký bằng CCCD' : 'Tạo tài khoản mới'}</p>
        </Logo>

        {error && <ErrorMessage>{error}</ErrorMessage>}
        {cccdExists && <ErrorMessage>CCCD này đã được đăng ký. Vui lòng đăng nhập hoặc sử dụng CCCD khác.</ErrorMessage>}

        <Form onSubmit={handleSubmit}>
          {!isCCCD ? (
            <>
              <InputGroup>
                <InputIcon>
                  <FiUser />
                </InputIcon>
                <Input
                  type="text"
                  name="username"
                  placeholder="Tên đăng nhập"
                  value={formData.username}
                  onChange={handleChange}
                  required
                />
              </InputGroup>

              <InputGroup>
                <InputIcon>
                  <FiMail />
                </InputIcon>
                <Input
                  type="email"
                  name="email"
                  placeholder="Địa chỉ email"
                  value={formData.email}
                  onChange={handleChange}
                  required
                />
              </InputGroup>

              <InputGroup>
                <InputIcon>
                  <FiLock />
                </InputIcon>
                <Input
                  type={showPassword ? 'text' : 'password'}
                  name="password"
                  placeholder="Mật khẩu"
                  value={formData.password}
                  onChange={handleChange}
                  required
                />
                <PasswordToggle
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <FiEyeOff /> : <FiEye />}
                </PasswordToggle>
              </InputGroup>

              <InputGroup>
                <InputIcon>
                  <FiLock />
                </InputIcon>
                <Input
                  type={showConfirmPassword ? 'text' : 'password'}
                  name="confirmPassword"
                  placeholder="Xác nhận mật khẩu"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  required
                />
                <PasswordToggle
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                >
                  {showConfirmPassword ? <FiEyeOff /> : <FiEye />}
                </PasswordToggle>
              </InputGroup>

              <Button type="submit" disabled={loading}>
                {loading ? 'Đang tạo tài khoản...' : 'Đăng ký'}
              </Button>

              <Divider>hoặc</Divider>

              <CCCDButton 
                type="button" 
                onClick={handleCCCDRegister}
                disabled={loading}
              >
                <FiCreditCard /> Đăng ký bằng CCCD
              </CCCDButton>
            </>
          ) : (
            <>
              <InputGroup>
                <InputIcon>
                  <FiUser />
                </InputIcon>
                <Input
                  type="text"
                  name="fullName"
                  placeholder="Họ và tên"
                  value={formData.fullName || ''}
                  onChange={handleChange}
                  required
                />
              </InputGroup>

              <InputGroup>
                <InputIcon>
                  <FiCreditCard />
                </InputIcon>
                <Input
                  type="text"
                  name="cccd"
                  placeholder="Số CCCD"
                  value={formData.cccd || ''}
                  onChange={handleChange}
                  required
                  disabled
                />
              </InputGroup>

              <InputGroup>
                <InputIcon>
                  <FiCalendar />
                </InputIcon>
                <Input
                  type="date"
                  name="dateOfBirth"
                  placeholder="Ngày sinh"
                  value={formData.dateOfBirth || ''}
                  onChange={handleChange}
                  required
                />
              </InputGroup>

              <InputGroup>
                <InputIcon />
                <div style={{ display: 'flex', gap: '1rem' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                    <input
                      type="radio"
                      name="gender"
                      value="Nam"
                      checked={formData.gender === 'Nam'}
                      onChange={handleChange}
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
                      onChange={handleChange}
                    />
                    Nữ
                  </label>
                </div>
              </InputGroup>

              <InputGroup>
                <InputIcon>
                  <FiUser />
                </InputIcon>
                <Input
                  type="text"
                  name="address"
                  placeholder="Địa chỉ"
                  value={formData.address || ''}
                  onChange={handleChange}
                  required
                />
              </InputGroup>

              <InputGroup>
                <InputIcon>
                  <FiMail />
                </InputIcon>
                <Input
                  type="email"
                  name="email"
                  placeholder="Địa chỉ email"
                  value={formData.email}
                  onChange={handleChange}
                  required
                />
              </InputGroup>

              <InputGroup>
                <InputIcon>
                  <FiLock />
                </InputIcon>
                <Input
                  type={showPassword ? 'text' : 'password'}
                  name="password"
                  placeholder="Mật khẩu"
                  value={formData.password}
                  onChange={handleChange}
                  required
                />
                <PasswordToggle
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <FiEyeOff /> : <FiEye />}
                </PasswordToggle>
              </InputGroup>

              <InputGroup>
                <InputIcon>
                  <FiLock />
                </InputIcon>
                <Input
                  type={showConfirmPassword ? 'text' : 'password'}
                  name="confirmPassword"
                  placeholder="Xác nhận mật khẩu"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  required
                />
                <PasswordToggle
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                >
                  {showConfirmPassword ? <FiEyeOff /> : <FiEye />}
                </PasswordToggle>
              </InputGroup>

              <Button type="submit" disabled={loading}>
                {loading ? 'Đang tạo tài khoản...' : 'Hoàn tất đăng ký'}
              </Button>
            </>
          )}
        </Form>

        <LinkText>
          Đã có tài khoản? <Link to="/login">Đăng nhập ngay</Link>
        </LinkText>
      </RegisterCard>
    </RegisterContainer>
  );
};

export default Register;
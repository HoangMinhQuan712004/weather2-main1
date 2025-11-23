import React, { useEffect, useState } from 'react';
import styled from 'styled-components';
import toast from 'react-hot-toast';

const Card = styled.div`
  background: var(--card-background);
  color: var(--text-color);
  border-radius: 12px;
  padding: 16px;
  box-shadow: 0 6px 18px rgba(0,0,0,0.08);
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
`;

const Icon = styled.div`
  width: 48px;
  height: 48px;
  border-radius: 10px;
  background: var(--primary-accent);
  display:flex;align-items:center;justify-content:center;color:white;font-weight:700;
`;

const Body = styled.div`
  flex: 1;
`;

const Title = styled.div`
  font-weight:700;
  margin-bottom:4px;
`;

const Message = styled.div`
  opacity:0.9;
  font-size:0.95rem;
`;

const Actions = styled.div`
  display:flex;gap:8px;margin-left:12px;
`;

const Button = styled.button`
  background: transparent;
  color: var(--primary-accent);
  border: 1px solid var(--primary-accent);
  padding:6px 10px;border-radius:8px;cursor:pointer;font-weight:600;
`;

// Simple reminder storage key
const REMINDERS_KEY = 'weather_reminders_v1';

const SuggestionCard = ({ suggestion }) => {
  const [isReminderSet, setIsReminderSet] = useState(false);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(REMINDERS_KEY);
      const list = raw ? JSON.parse(raw) : [];
      const exists = list.some(r => r.id === suggestion.id);
      setIsReminderSet(Boolean(exists));
    } catch (e) {
      // ignore
    }
  }, [suggestion.id]);

  const setReminder = (minutes = 30) => {
    try {
      const fireAt = Date.now() + minutes * 60 * 1000;
      const raw = localStorage.getItem(REMINDERS_KEY);
      const list = raw ? JSON.parse(raw) : [];
      // avoid duplicates
      if (!list.some(r => r.id === suggestion.id)) {
        list.push({ id: suggestion.id, fireAt, title: suggestion.title, message: suggestion.message });
        localStorage.setItem(REMINDERS_KEY, JSON.stringify(list));
      }
      setIsReminderSet(true);
      toast.success(`Đã đặt nhắc nhở ${minutes} phút`);

      // Schedule in-session notification
      setTimeout(() => {
        toast(`Nhắc: ${suggestion.title} — ${suggestion.message}`);
      }, minutes * 60 * 1000);
    } catch (e) {
      console.error('Failed to set reminder', e);
      toast.error('Không thể đặt nhắc nhở');
    }
  };

  const clearReminder = () => {
    try {
      const raw = localStorage.getItem(REMINDERS_KEY);
      const list = raw ? JSON.parse(raw) : [];
      const rest = list.filter(r => r.id !== suggestion.id);
      localStorage.setItem(REMINDERS_KEY, JSON.stringify(rest));
      setIsReminderSet(false);
      toast.success('Đã huỷ nhắc nhở');
    } catch (e) {
      console.error('Failed to clear reminder', e);
      toast.error('Không thể huỷ nhắc nhở');
    }
  };

  return (
    <Card role="region" aria-label={`Suggestion ${suggestion.title}`}>
      <Icon>{suggestion.icon === 'rain' ? '☔' : '!'}</Icon>
      <Body>
        <Title>{suggestion.title}</Title>
        <Message>{suggestion.message}</Message>
      </Body>
      <Actions>
        {!isReminderSet ? (
          <Button onClick={() => setReminder(30)}>Nhắc 30 phút</Button>
        ) : (
          <Button onClick={clearReminder}>Huỷ nhắc</Button>
        )}
        <Button onClick={() => toast(suggestion.message)}>Xem</Button>
      </Actions>
    </Card>
  );
};

export default SuggestionCard;

import React from 'react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';
import styled from 'styled-components';

// Fix for default icon issue with Webpack
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: require('leaflet/dist/images/marker-icon-2x.png'),
  iconUrl: require('leaflet/dist/images/marker-icon.png'),
  shadowUrl: require('leaflet/dist/images/marker-shadow.png'),
});

const MapWrapper = styled.div`
  height: 400px;
  width: 100%;
  border-radius: 15px;
  overflow: hidden;
  margin-top: 20px;
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);

  .leaflet-container {
    height: 100%;
    width: 100%;
  }
`;

const WeatherMap = ({ lat, lon, cityName }) => {
  if (!lat || !lon) {
    return <MapWrapper><p style={{ textAlign: 'center', padding: '20px', color: 'var(--text-color-light)' }}>Map data not available.</p></MapWrapper>;
  }

  const position = [lat, lon];

  return (
    <MapWrapper>
      <MapContainer center={position} zoom={10} scrollWheelZoom={false} style={{ height: '100%', width: '100%' }}>
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        <Marker position={position}>
          <Popup>
            {cityName || 'Weather Location'}
          </Popup>
        </Marker>
      </MapContainer>
    </MapWrapper>
  );
};

export default WeatherMap;

import React from 'react';
import ReactDOM from 'react-dom/client';
import { Popup } from '../popup/Popup';

const root = document.getElementById('root');
if (root) {
  ReactDOM.createRoot(root).render(
    React.createElement(React.StrictMode, null,
      React.createElement(Popup)
    )
  );
}
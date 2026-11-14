import React from 'react';
import ErrorBoundary from './components/ErrorBoundary';

export function App(): React.ReactElement {
  return (
    <ErrorBoundary>
      <main>
        <h1>TTL-Legacy Vault Dashboard</h1>
      </main>
    </ErrorBoundary>
  );
}

export default App;

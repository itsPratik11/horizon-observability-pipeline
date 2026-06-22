import React, { useState, useEffect } from 'react';

function App() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const eventSource = new EventSource('http://localhost:8080/api/v1/logs/stream');
    eventSource.onmessage = (event) => {
        const newLog = JSON.parse(event.data);
        setLogs((prevLogs) => [newLog, ...prevLogs].slice(0, 50)); 
    };
    return () => eventSource.close();
  }, []);

  const getBadgeColor = (type) => {
      if (type === 'SECURITY_THREAT') return 'bg-red-600 text-white';
      if (type === 'SYSTEM_FAULT') return 'bg-orange-500 text-white';
      return 'bg-green-500 text-white';
  };

  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 p-8 font-sans">
        <header className="mb-8">
            <h1 className="text-4xl font-extrabold text-blue-400 tracking-tight">Horizon</h1>
            <p className="text-gray-400 mt-1">Intelligent Log Orchestration & Observability Pipeline</p>
        </header>
        <div className="bg-gray-800 rounded-xl shadow-2xl border border-gray-700 overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-700 flex justify-between items-center bg-gray-800/50">
                <h2 className="text-lg font-semibold text-gray-200">Live Event Stream</h2>
                <span className="flex h-3 w-3 relative">
                  <span className="animate-ping absolute inline-flex h-3 w-3 rounded-full bg-green-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
                </span>
            </div>
            <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
                <table className="w-full text-left border-collapse">
                    <thead className="bg-gray-700/50 sticky top-0 backdrop-blur-sm">
                        <tr className="text-xs uppercase tracking-wider text-gray-400">
                            <th className="px-6 py-3 font-medium">Timestamp</th>
                            <th className="px-6 py-3 font-medium">AI Classification</th>
                            <th className="px-6 py-3 font-medium">System Path</th>
                            <th className="px-6 py-3 font-medium">Raw Message</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-700">
                        {logs.length === 0 && (
                            <tr>
                                <td colSpan="4" className="px-6 py-8 text-center text-gray-500 italic">
                                    Waiting for incoming server logs...
                                </td>
                            </tr>
                        )}
                        {logs.map((log, idx) => (
                            <tr key={idx} className="hover:bg-gray-750 transition-colors duration-150">
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300 font-mono">
                                    {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString()}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <span className={`px-3 py-1 text-xs font-bold rounded-full shadow-sm ${getBadgeColor(log.classifiedType)}`}>
                                        {log.classifiedType || 'UNCLASSIFIED'}
                                    </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-blue-300 font-mono">
                                    {log.systemPath || 'UNKNOWN'}
                                </td>
                                <td className="px-6 py-4 text-sm text-gray-400 font-mono truncate max-w-md">
                                    {log.rawMessage}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
  );
}

export default App;

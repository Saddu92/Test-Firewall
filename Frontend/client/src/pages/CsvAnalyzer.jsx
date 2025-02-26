import React, { useState } from "react";
import axios from "axios";
import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend, PieChart, Pie, Cell } from "recharts";

function CsvAnalyzer() {
  const [loading, setLoading] = useState(false);
  const [predictions, setPredictions] = useState([]);
  const [alert, setAlert] = useState("");
  const [packetData, setPacketData] = useState([]);

  // Handle file upload
  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;
  
    setLoading(true);
    setAlert("");
    setPredictions([]);
    setPacketData([]);
  
    const formData = new FormData();
    formData.append("file", file);
  
    try {
      const response = await fetch("http://127.0.0.1:8000/predict-csv", {
        method: "POST",
        body: formData,
      });
  
      // Check if the response is OK (status code 200-299)
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
  
      // Parse the response as JSON
      const data = await response.json();
      console.log("Response Data:", data); // Log the response data for debugging
  
      // Check if the required fields exist in the response
      if (!data.predictions || !data.packet_data) {
        throw new Error("Invalid response format from server");
      }
  
      // Update state with the response data
      setPredictions(data.predictions);
      setPacketData(data.packet_data);
  
      // Show an alert if a threat is detected
      if (data.predictions.includes(1)) {
        setAlert("🚨 Suspicious Network Activity Detected!");
      }
    } catch (error) {
      console.error("Error:", error);
      setAlert("Failed to process the CSV file.");
    } finally {
      setLoading(false);
    }
  };

  // Data for charts
  const chartData = predictions.map((val, index) => ({ id: index + 1, status: val ? "Threat" : "Normal" }));
  const pieData = [
    { name: "Normal", value: predictions.filter((p) => p === 0).length },
    { name: "Threat", value: predictions.filter((p) => p === 1).length },
  ];
  const colors = ["#34D399", "#F87171"]; // Green for Normal, Red for Threat

  return (
    <div className="min-h-screen bg-gray-900 text-white flex flex-col items-center p-8">
      <h1 className="text-3xl font-bold">CSV Packet Analyzer</h1>

      {alert && <div className="bg-red-500 p-2 rounded mt-3">{alert}</div>}

      <div className="mt-5">
        <input
          type="file"
          accept=".csv"
          onChange={handleFileUpload}
          className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
          disabled={loading}
        />
      </div>

      {loading && <div className="mt-3">Processing CSV file...</div>}

      {predictions.length > 0 && (
        <div className="w-full flex flex-col items-center mt-6">
          <div className="w-full flex justify-between">
            <div className="w-1/2">
              <h2 className="text-xl font-semibold">Packet Predictions</h2>
              <BarChart width={400} height={250} data={chartData}>
                <XAxis dataKey="id" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="status" fill="#8884d8" />
              </BarChart>
            </div>
            <div className="w-1/2">
              <h2 className="text-xl font-semibold">Threat Analysis</h2>
              <PieChart width={250} height={250}>
                <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80}>
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={colors[index]} />
                  ))}
                </Pie>
              </PieChart>
            </div>
          </div>

          <div className="w-full mt-8">
            <h2 className="text-xl font-semibold">Packet Data with Predictions</h2>
            <div className="overflow-x-auto">
              <table className="min-w-full bg-gray-800 text-white">
                <thead>
                  <tr>
                    <th className="px-4 py-2">Packet ID</th>
                    <th className="px-4 py-2">Source IP</th>
                    <th className="px-4 py-2">Destination IP</th>
                    <th className="px-4 py-2">Protocol</th>
                    <th className="px-4 py-2">Source Port</th>
                    <th className="px-4 py-2">Destination Port</th>
                    <th className="px-4 py-2">Packet Length</th>
                    <th className="px-4 py-2">Prediction</th>
                  </tr>
                </thead>
                <tbody>
                  {packetData.map((packet, index) => (
                    <tr key={index} className="border-b border-gray-700">
                      <td className="px-4 py-2">{index + 1}</td>
                      <td className="px-4 py-2">{packet['Source IP'] || 'N/A'}</td>
                      <td className="px-4 py-2">{packet['Destination IP'] || 'N/A'}</td>
                      <td className="px-4 py-2">{packet['Protocol'] || 'N/A'}</td>
                      <td className="px-4 py-2">{packet['Source Port'] || 'N/A'}</td>
                      <td className="px-4 py-2">{packet['Destination Port'] || 'N/A'}</td>
                      <td className="px-4 py-2">{packet['Packet Length'] || 'N/A'}</td>
                      <td className="px-4 py-2">
                        <span className={`px-2 py-1 rounded ${predictions[index] === 1 ? 'bg-red-500' : 'bg-green-500'}`}>
                          {predictions[index] === 1 ? 'Threat' : 'Normal'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default CsvAnalyzer;
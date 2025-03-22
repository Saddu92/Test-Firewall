import React, { useState, useEffect } from "react";
import axios from "axios";
import { useLocation } from "react-router-dom";
import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend, PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import { toast, ToastContainer } from "react-toastify";

function PacketCapture() {
  const [loading, setLoading] = useState(false);
  const [predictions, setPredictions] = useState([]);
  const [alert, setAlert] = useState("");
  const [packetData, setPacketData] = useState([]);
  const location = useLocation();
  const userEmail = location.state?.userEmail || ""; // Get user email from login

  // Function to start packet capture and prediction
  const startCapture = async () => {
    setLoading(true);
    setAlert("");
    try {
      const response = await axios.post("http://127.0.0.1:8000/start-capture-and-predict/", {
        user_email: userEmail, // Pass user email to backend
      });
      setPredictions(response.data.predictions);
      setPacketData(response.data.packet_data);

      // Show an alert if a threat is detected
      if (response.data.predictions.includes(1)) {
        toast("🚨 Suspicious Network Activity Detected!");
      }
    } catch (error) {
      console.error("Error:", error);
      setAlert("Failed to start packet capture.");
    } finally {
      setLoading(false);
    }
  };

  // Function to drop packets from a specific IP
  const dropPackets = async (ip) => {
    try {
      await axios.post("http://127.0.0.1:8000/drop-packets/", { ip });
      alert(`Packets from ${ip} have been dropped.`);
    } catch (error) {
      console.error("Error dropping packets:", error);
      toast.error("Failed to drop packets.");
    }
  };

  // Data for charts
  const chartData = predictions.map((val, index) => ({ id: index + 1, status: val ? "Threat" : "Normal" }));
  const pieData = [
    { name: "Normal", value: predictions.filter((p) => p === 0).length },
    { name: "Threat", value: predictions.filter((p) => p === 1).length },
  ];
  const colors = ["#34D399", "#F87171"]; // Green for Normal, Red for Threat

  // Custom Tooltip for BarChart
  const CustomBarTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-gray-800 p-3 rounded-lg shadow-lg border border-gray-700">
          <p className="font-semibold">{`Packet ID: ${label}`}</p>
          <p>{`Status: ${payload[0].value}`}</p>
        </div>
      );
    }
    return null;
  };

  // Custom Tooltip for PieChart
  const CustomPieTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-gray-800 p-3 rounded-lg shadow-lg border border-gray-700">
          <p className="font-semibold">{`${payload[0].name}: ${payload[0].value}`}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white flex flex-col items-center p-8">
      <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-500 to-purple-600 bg-clip-text text-transparent">
        Proactive Firewall Dashboard
      </h1>

      {alert && (
        <div className="bg-red-500 p-3 rounded-lg mt-4 shadow-lg flex items-center">
          <span className="mr-2">🚨</span>
          {alert}
        </div>
      )}

      <button
        onClick={startCapture}
        className="bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white font-bold py-2 px-6 rounded-lg mt-6 transition-all duration-300 transform hover:scale-105"
        disabled={loading}
      >
        {loading ? "Capturing..." : "Start Packet Capture"}
      </button>

      {predictions.length > 0 && (
        <div className="w-full flex flex-col items-center mt-8">
          {/* Centered Graphs */}
          <div className="w-full max-w-4xl flex flex-col md:flex-row justify-center gap-6">
            {/* BarChart */}
            <div className="w-full md:w-1/2 bg-gray-800 p-6 rounded-lg shadow-lg">
              <h2 className="text-xl font-semibold mb-4 text-center">Packet Predictions</h2>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={chartData}>
                  <XAxis dataKey="id" stroke="#FFF" />
                  <YAxis stroke="#FFF" />
                  <Tooltip content={<CustomBarTooltip />} />
                  <Legend />
                  <Bar dataKey="status" fill="#8884d8" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* PieChart */}
            <div className="w-full md:w-1/2 bg-gray-800 p-6 rounded-lg shadow-lg">
              <h2 className="text-xl font-semibold mb-4 text-center">Threat Analysis</h2>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={pieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    label
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={colors[index]} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomPieTooltip />} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Table */}
          <div className="w-full mt-8 bg-gray-800 p-6 rounded-lg shadow-lg">
            <h2 className="text-xl font-semibold mb-4 flex justify-center items-center">Captured Packets with Predictions</h2>
            <div className="overflow-x-auto">
              <table className="min-w-full bg-gray-700 text-white rounded-lg">
                <thead>
                  <tr className="bg-gray-600">
                    <th className="px-4 py-3">Packet ID</th>
                    <th className="px-4 py-3">Source IP</th>
                    <th className="px-4 py-3">Destination IP</th>
                    <th className="px-4 py-3">Protocol</th>
                    <th className="px-4 py-3">Source Port</th>
                    <th className="px-4 py-3">Destination Port</th>
                    <th className="px-4 py-3">Packet Length</th>
                    <th className="px-4 py-3">Prediction</th>
                    <th className="px-4 py-3">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {packetData.map((packet, index) => (
                    <tr key={index} className="border-b border-gray-600 hover:bg-gray-650 transition-colors">
                      <td className="px-4 py-3 flex justify-center">{index + 1}</td>
                      <td className="px-4 py-3">{packet['Source IP']}</td>
                      <td className="px-4 py-3">{packet['Destination IP']}</td>
                      <td className="px-4 py-3">{packet['Protocol']}</td>
                      <td className="px-4 py-3">{packet['Source Port']}</td>
                      <td className="px-4 py-3">{packet['Destination Port']}</td>
                      <td className="px-4 py-3">{packet['Packet Length']}</td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 rounded ${predictions[index] === 1 ? 'bg-red-500' : 'bg-green-500'}`}>
                          {predictions[index] === 1 ? 'Threat' : 'Normal'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {predictions[index] === 1 && (
                          <button
                            onClick={() => dropPackets(packet['Source IP'])}
                            className="bg-red-500 hover:bg-red-600 text-white font-bold py-1 px-3 rounded-lg transition-all duration-300 transform hover:scale-105"
                          >
                            Drop Packets
                          </button>
                        )}
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

export default PacketCapture;
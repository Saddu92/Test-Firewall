import { Lock, Mail, Loader } from "lucide-react";
import Input from "../components/Input";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = (e) => {
    e.preventDefault();
    
    // Simulate a login process
    setIsLoading(true);
    setTimeout(() => {
      setIsLoading(false);
      // Navigate to packet-capture and pass the email
      navigate("/start-capture-and-predict", { state: { userEmail: email } });
    }, 2000);
  };

  return (
    <div className="max-w-md rounded-2xl shadow-xl bg-gray-300 items-center flex w-full justify-center my-20 mx-auto">
      <div className="p-8">
        <h2 className="text-3xl font-bold mb-6 text-center text-black">
          Welcome Back
        </h2>
        <form onSubmit={handleLogin}>
          <Input
            icon={Mail}
            type="email"
            placeholder="Email Address"
            className="mb-4 text-gray-900 bg-black outline-none"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <Input
            icon={Lock}
            type="password"
            placeholder="Password"
            className="mb-4 text-gray-900 bg-black outline-none"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <div className="flex justify-center items-center">
            <Link to="/forgot-password" className="text-sm">
              Forgot Password?
            </Link>
          </div>
          <button
            disabled={isLoading}
            type="submit"
            className="mt-5 w-full bg-black text-white p-3 rounded-md font-sans font-light hover:bg-gray-800"
          >
            {isLoading ? (
              <Loader className="w-6 h-6 animate-spin mx-auto" color="white" />
            ) : (
              "Login"
            )}
          </button>
        </form>

        <div className="px-8 py-4 bg-opacity-50">
          <p className="text-black text-center">
            Doesn&apos;t have an account?{" "}
            <Link to="/register" className="text-black">
              Register
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;

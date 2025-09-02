import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, Lock, Cloud, Download, Share, FileText } from 'lucide-react';

const HomePage = () => {
  const features = [
    {
      icon: <Shield className="w-8 h-8 text-primary-600" />,
      title: "End-to-End Encryption",
      description: "Your files are encrypted with AES-256 before upload, ensuring maximum security."
    },
    {
      icon: <Cloud className="w-8 h-8 text-primary-600" />,
      title: "Cloud Storage",
      description: "Secure cloud storage with AWS S3 infrastructure for reliable file access."
    },
    {
      icon: <Lock className="w-8 h-8 text-primary-600" />,
      title: "Access Control",
      description: "Only you can access your files with secure authentication and authorization."
    },
    {
      icon: <Share className="w-8 h-8 text-primary-600" />,
      title: "Secure Sharing",
      description: "Share files with expiring links while maintaining encryption security."
    },
    {
      icon: <Download className="w-8 h-8 text-primary-600" />,
      title: "Easy Downloads",
      description: "Download your files anytime with automatic decryption on your device."
    },
    {
      icon: <FileText className="w-8 h-8 text-primary-600" />,
      title: "File Management",
      description: "Organize, rename, and manage your files with an intuitive dashboard."
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-white">
      {/* Header */}
      <header className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <Shield className="w-8 h-8 text-primary-600 mr-3" />
              <h1 className="text-2xl font-bold text-gray-900">SecureVault</h1>
            </div>
            <div className="flex space-x-4">
              <Link to="/login" className="btn-secondary">
                Login
              </Link>
              <Link to="/register" className="btn-primary">
                Get Started
              </Link>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-5xl font-bold text-gray-900 mb-6">
            Secure Cloud Storage with
            <span className="text-primary-600"> End-to-End Encryption</span>
          </h2>
          <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto">
            Store, manage, and share your files with military-grade AES-256 encryption. 
            Your data is protected at every step - from upload to download.
          </p>
          <div className="flex justify-center space-x-4">
            <Link to="/register" className="btn-primary text-lg px-8 py-3">
              Start Encrypting Files
            </Link>
            <Link to="/login" className="btn-secondary text-lg px-8 py-3">
              Access Your Vault
            </Link>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h3 className="text-3xl font-bold text-gray-900 mb-4">
              Why Choose SecureVault?
            </h3>
            <p className="text-lg text-gray-600">
              Built with security-first principles and modern encryption standards
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((feature, index) => (
              <div key={index} className="card p-6 text-center hover:shadow-lg transition-shadow">
                <div className="flex justify-center mb-4">
                  {feature.icon}
                </div>
                <h4 className="text-xl font-semibold text-gray-900 mb-2">
                  {feature.title}
                </h4>
                <p className="text-gray-600">
                  {feature.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Security Section */}
      <section className="py-20 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div>
              <h3 className="text-3xl font-bold text-gray-900 mb-6">
                Enterprise-Grade Security
              </h3>
              <div className="space-y-4">
                <div className="flex items-start">
                  <Lock className="w-6 h-6 text-primary-600 mr-3 mt-1" />
                  <div>
                    <h4 className="font-semibold text-gray-900">AES-256 Encryption</h4>
                    <p className="text-gray-600">Military-grade encryption used by governments worldwide</p>
                  </div>
                </div>
                <div className="flex items-start">
                  <Shield className="w-6 h-6 text-primary-600 mr-3 mt-1" />
                  <div>
                    <h4 className="font-semibold text-gray-900">Zero-Knowledge Architecture</h4>
                    <p className="text-gray-600">We can't see your files even if we wanted to</p>
                  </div>
                </div>
                <div className="flex items-start">
                  <Cloud className="w-6 h-6 text-primary-600 mr-3 mt-1" />
                  <div>
                    <h4 className="font-semibold text-gray-900">Secure Cloud Infrastructure</h4>
                    <p className="text-gray-600">Built on AWS with additional encryption layers</p>
                  </div>
                </div>
              </div>
            </div>
            <div className="bg-white p-8 rounded-lg shadow-lg">
              <h4 className="text-xl font-semibold text-gray-900 mb-4">How It Works</h4>
              <div className="space-y-4">
                <div className="flex items-center">
                  <div className="w-8 h-8 bg-primary-600 text-white rounded-full flex items-center justify-center text-sm font-semibold mr-3">1</div>
                  <p className="text-gray-700">Upload your file through our secure interface</p>
                </div>
                <div className="flex items-center">
                  <div className="w-8 h-8 bg-primary-600 text-white rounded-full flex items-center justify-center text-sm font-semibold mr-3">2</div>
                  <p className="text-gray-700">File is encrypted with AES-256 before leaving your device</p>
                </div>
                <div className="flex items-center">
                  <div className="w-8 h-8 bg-primary-600 text-white rounded-full flex items-center justify-center text-sm font-semibold mr-3">3</div>
                  <p className="text-gray-700">Encrypted file is stored securely in the cloud</p>
                </div>
                <div className="flex items-center">
                  <div className="w-8 h-8 bg-primary-600 text-white rounded-full flex items-center justify-center text-sm font-semibold mr-3">4</div>
                  <p className="text-gray-700">Download and decrypt only with your credentials</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-primary-600">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h3 className="text-3xl font-bold text-white mb-4">
            Ready to Secure Your Files?
          </h3>
          <p className="text-xl text-primary-100 mb-8">
            Join thousands of users who trust SecureVault with their sensitive data
          </p>
          <Link to="/register" className="bg-white text-primary-600 hover:bg-gray-100 font-medium py-3 px-8 rounded-lg transition-colors duration-200">
            Create Free Account
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-900 text-white py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <Shield className="w-6 h-6 text-primary-400 mr-2" />
              <span className="text-lg font-semibold">SecureVault</span>
            </div>
            <p className="text-gray-400">
              © 2024 SecureVault. Your files, encrypted and secure.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default HomePage;

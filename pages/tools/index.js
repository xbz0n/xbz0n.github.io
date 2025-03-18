import Layout from '../../components/Layout';
import Link from 'next/link';
import { FaGithub, FaDownload } from 'react-icons/fa';

export default function Tools() {
  const tools = [
    {
      name: 'GoPhish Deploy',
      description: 'Python script to automate the deployment and configuration of the GoPhish phishing framework. The script installs all necessary dependencies, configures SSL certificates, and sets up the environment for a production-ready deployment.',
      github: 'https://github.com/xbz0n/gophish-deploy',
      features: [
        'Automated dependency installation',
        'SSL certificate configuration',
        'Production-ready environment setup',
        'Security hardening',
        'Easy deployment process'
      ]
    }
  ];

  return (
    <Layout>
      <div className="container py-12">
        <h1 className="text-4xl font-bold mb-8">Tools</h1>
        
        <div className="grid gap-8">
          {tools.map((tool, index) => (
            <div key={index} className="bg-secondary/50 rounded-lg p-6 border border-gray-700">
              <div className="flex justify-between items-start mb-4">
                <h2 className="text-2xl font-bold text-accent">{tool.name}</h2>
                <div className="flex space-x-4">
                  <a
                    href={tool.github}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-gray-300 hover:text-accent flex items-center space-x-2"
                  >
                    <FaGithub className="w-5 h-5" />
                    <span>GitHub</span>
                  </a>
                  <a
                    href={`${tool.github}/archive/refs/heads/main.zip`}
                    className="text-gray-300 hover:text-accent flex items-center space-x-2"
                  >
                    <FaDownload className="w-5 h-5" />
                    <span>Download</span>
                  </a>
                </div>
              </div>
              
              <p className="text-gray-300 mb-4">{tool.description}</p>
              
              <div className="mt-4">
                <h3 className="text-lg font-semibold mb-2">Features:</h3>
                <ul className="list-disc list-inside space-y-1 text-gray-300">
                  {tool.features.map((feature, idx) => (
                    <li key={idx}>{feature}</li>
                  ))}
                </ul>
              </div>
            </div>
          ))}
        </div>
      </div>
    </Layout>
  );
} 
import ToolCard from '../components/ToolCard';

export default function Tools() {
  const tools = [
    {
      name: "GoPhish Deploy",
      repo: "https://github.com/xbz0n/gophish-deploy",
      description: "Python script to automate the deployment and configuration of the GoPhish phishing framework. The script installs all necessary dependencies, configures SSL certificates, and sets up the environment for a production-ready deployment.",
      features: [
        'Automated dependency installation',
        'SSL certificate configuration',
        'Production-ready environment setup',
        'Security hardening',
        'Easy deployment process'
      ],
      liveLink: null
    }
  ];

  return (
    <div className="space-y-8">
      <div className="space-y-4">
        <h1 className="text-3xl font-bold">Tools</h1>
        <p className="text-gray-400">
          Open-source security tools and utilities developed to assist with penetration testing, 
          vulnerability research, and security assessments.
        </p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {tools.map((tool, index) => (
          <ToolCard 
            key={index}
            name={tool.name}
            repo={tool.repo}
            description={tool.description}
            features={tool.features}
            liveLink={tool.liveLink}
          />
        ))}
      </div>
    </div>
  );
} 
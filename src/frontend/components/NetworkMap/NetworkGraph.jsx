import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import './NetworkGraph.css';

/**
 * Network Graph Component
 * 
 * Renders an interactive network graph visualizing devices and connections
 * with highlighting for suspicious activity.
 */
const NetworkGraph = ({
  devices = [],
  connections = [],
  alerts = [],
  width = 800,
  height = 600,
  onNodeSelect,
  onNodeHover,
  className,
  lite = false
}) => {
  const svgRef = useRef(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const simulationRef = useRef(null);

  // Process data to include alert information
  const processedDevices = React.useMemo(() => {
    return devices.map(device => {
      // Count alerts for this device
      const deviceAlerts = alerts.filter(
        alert => alert.sourceDeviceId === device.id || alert.targetDeviceId === device.id
      );
      
      return {
        ...device,
        alerts: deviceAlerts,
        alertCount: deviceAlerts.length,
        severity: deviceAlerts.length > 0 ? 
          Math.max(...deviceAlerts.map(a => a.severityLevel)) : 0
      };
    });
  }, [devices, alerts]);

  // Process connections to include alert information
  const processedConnections = React.useMemo(() => {
    return connections.map(connection => {
      // Find alerts for this connection
      const connectionAlerts = alerts.filter(
        alert => 
          (alert.sourceDeviceId === connection.source && alert.targetDeviceId === connection.target) ||
          (alert.sourceDeviceId === connection.target && alert.targetDeviceId === connection.source)
      );
      
      return {
        ...connection,
        alerts: connectionAlerts,
        alertCount: connectionAlerts.length,
        severity: connectionAlerts.length > 0 ? 
          Math.max(...connectionAlerts.map(a => a.severityLevel)) : 0
      };
    });
  }, [connections, alerts]);

  // Initialize and update network graph
  useEffect(() => {
    if (!svgRef.current || processedDevices.length === 0) return;

    // Clear previous graph
    d3.select(svgRef.current).selectAll("*").remove();

    // Set up SVG container
    const svg = d3.select(svgRef.current)
      .attr("width", width)
      .attr("height", height);

    // Create a group for all elements
    const g = svg.append("g")
      .attr("class", "network-graph-container");

    // Define zoom behavior
    const zoom = d3.zoom()
      .scaleExtent([0.1, 5])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });

    // Apply zoom to SVG
    svg.call(zoom);

    // Create links
    const link = g.append("g")
      .attr("class", "links")
      .selectAll("line")
      .data(processedConnections)
      .enter()
      .append("line")
      .attr("class", d => `link ${d.alertCount > 0 ? 'alert' : 'normal'}`)
      .attr("stroke-width", d => 1 + (d.alertCount * 0.5))
      .attr("stroke", d => getConnectionColor(d));

    // Create nodes
    const node = g.append("g")
      .attr("class", "nodes")
      .selectAll("g")
      .data(processedDevices)
      .enter()
      .append("g")
      .attr("class", "node")
      .call(d3.drag()
        .on("start", dragStarted)
        .on("drag", dragged)
        .on("end", dragEnded))
      .on("click", (event, d) => {
        setSelectedNode(d);
        if (onNodeSelect) onNodeSelect(d);
      })
      .on("mouseover", (event, d) => {
        setHoveredNode(d);
        if (onNodeHover) onNodeHover(d);
      })
      .on("mouseout", () => {
        setHoveredNode(null);
        if (onNodeHover) onNodeHover(null);
      });

    // Add circles to nodes
    node.append("circle")
      .attr("r", d => 5 + (d.alertCount * 2))
      .attr("fill", d => getNodeColor(d))
      .attr("class", d => `node-circle ${d.alertCount > 0 ? 'alert' : 'normal'}`);

    // Add device icons
    node.append("text")
      .attr("dy", 4)
      .attr("text-anchor", "middle")
      .text(d => getDeviceIcon(d))
      .attr("class", "device-icon");

    // Add labels
    node.append("text")
      .attr("dy", 20)
      .attr("text-anchor", "middle")
      .text(d => d.name || d.ipAddress)
      .attr("class", "device-label");

    // Create the force simulation
    const simulation = d3.forceSimulation(processedDevices)
      .force("link", d3.forceLink(processedConnections)
        .id(d => d.id)
        .distance(100))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(30))
      .on("tick", () => {
        link
          .attr("x1", d => d.source.x)
          .attr("y1", d => d.source.y)
          .attr("x2", d => d.target.x)
          .attr("y2", d => d.target.y);

        node
          .attr("transform", d => `translate(${d.x},${d.y})`);
      });

    // Save simulation reference
    simulationRef.current = simulation;

    // Drag functions
    function dragStarted(event, d) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function dragged(event, d) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragEnded(event, d) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }

    // Cleanup
    return () => {
      if (simulationRef.current) {
        simulationRef.current.stop();
      }
    };
  }, [processedDevices, processedConnections, width, height, onNodeSelect, onNodeHover]);

  // Helper functions for colors and icons
  const getNodeColor = (device) => {
    if (device.alertCount > 0) {
      switch (device.severity) {
        case 3: return '#FF3A33'; // Critical
        case 2: return '#FF9A33'; // High
        case 1: return '#FFDD33'; // Medium
        default: return '#33A0FF'; // Low
      }
    }
    if (device.isGateway) return '#33FF8B'; // Gateway
    return '#6E7B8B'; // Normal device
  };

  const getConnectionColor = (connection) => {
    if (connection.alertCount > 0) {
      switch (connection.severity) {
        case 3: return '#FF3A33'; // Critical
        case 2: return '#FF9A33'; // High
        case 1: return '#FFDD33'; // Medium
        default: return '#33A0FF'; // Low
      }
    }
    return '#CCCCCC'; // Normal connection
  };

  const getDeviceIcon = (device) => {
    if (device.isGateway) return '🌐';
    switch (device.deviceType) {
      case 'computer': return '💻';
      case 'mobile': return '📱';
      case 'server': return '🖥️';
      case 'printer': return '🖨️';
      case 'iot': return '🔌';
      default: return '📟';
    }
  };

  return (
    <div className={`network-graph-wrapper ${className || ''} ${lite ? 'lite-mode' : ''}`}>
      <svg ref={svgRef} className="network-graph"></svg>
      {selectedNode && (
        <div className="node-details">
          <h3>{selectedNode.name || selectedNode.ipAddress}</h3>
          <p>IP: {selectedNode.ipAddress}</p>
          <p>MAC: {selectedNode.macAddress}</p>
          {selectedNode.alertCount > 0 && (
            <div className="alert-badge">
              ⚠️ {selectedNode.alertCount} Alert{selectedNode.alertCount !== 1 ? 's' : ''}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default NetworkGraph; 
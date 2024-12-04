import { useState, useEffect } from "react";
import { Button } from "./components/ui/button";
import { ConnectionChart } from "./components/connection_chart";
import "./App.css";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

function App() {
  const serverUrl = "http://localhost:1234";
  const connectionsUrl = serverUrl + "/connections";
  const devicesUrl = serverUrl + "/devices";
  const [connections, setConnections] = useState({});
  const [devices, setDevices] = useState({});
  const [shouldUpdate, setShouldUpdate] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState("");
  const [selectedDeviceName, setSelectedDeviceName] = useState("(none)");

  const fetchConnections = () => {
    fetch(connectionsUrl)
      .then((response) => response.json())
      .then((data) => {
        setConnections(data);
      });
  };

  const fetchDevices = () => {
    fetch(devicesUrl)
      .then((response) => response.json())
      .then((data) => {
        setDevices(data);
        console.log(data);
      });
  };

  useEffect(() => {
    fetchConnections();
    fetchDevices();
  }, [shouldUpdate]);

  const updateSelectedDevice = (device: string) => {
    setSelectedDevice(device);
    setSelectedDeviceName(devices[device].device_name);
  };

  return (
    <div className="flex-1 flex-col h-screen">
      <div className="flex-grow">
        <ConnectionChart
          chartData={connections[selectedDevice]}
          deviceName={selectedDeviceName}
        />
      </div>
      <div>
        <Accordion type="single" collapsible>
          <AccordionItem value="devices">
            <AccordionTrigger className="text-primary-foreground">
              <h2 className="text-primary-foreground">Devices</h2>
            </AccordionTrigger>
            <AccordionContent>
              {Object.keys(devices).map((key) => (
                <div key={key}>
                  <p>
                    <Button
                      variant="outline"
                      onClick={() => updateSelectedDevice(key)}
                    >
                      Select {": "}
                      {key}, {devices[key].device_name}
                    </Button>
                  </p>
                </div>
              ))}
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </div>
      <div>
        <Button onClick={() => setShouldUpdate(!shouldUpdate)}>Refresh</Button>
      </div>
    </div>
  );
}

export default App;

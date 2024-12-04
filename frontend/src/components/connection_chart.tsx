"use client";

import { Activity, TrendingUp } from "lucide-react";
import { Area, AreaChart, CartesianGrid, XAxis } from "recharts";

import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
} from "@/components/ui/chart";

interface ConnectionChartProps {
  chartData: { timestamp: string; status: number }[];
  deviceName: string;
}

const chartConfig = {
  desktop: {
    label: "Connection Status",
    color: "hsl(var(--chart-2))",
    icon: Activity,
  },
} satisfies ChartConfig;

export function ConnectionChart({
  chartData,
  deviceName,
}: ConnectionChartProps) {
  return (
    <Card className="h-[65%]">
      <CardHeader>
        <CardTitle>{deviceName} connection status</CardTitle>
        <CardDescription>
          Displaying connection status of the selected device over time
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ChartContainer config={chartConfig}>
          <AreaChart
            accessibilityLayer
            data={chartData}
            margin={{
              left: 12,
              right: 12,
            }}
          >
            <CartesianGrid vertical={false} />
            <XAxis
              dataKey="timestamp"
              tickLine={false}
              axisLine={false}
              tickMargin={4}
              tickFormatter={(timestamp) =>
                new Date(timestamp).toLocaleDateString("en-US", {
                  day: "2-digit",
                  month: "short",
                  hour: "2-digit",
                  minute: "2-digit",
                })
              }
            />
            <ChartTooltip
              cursor={false}
              labelFormatter={(timestamp) =>
                new Date(timestamp).toLocaleDateString("en-US", {
                  day: "2-digit",
                  month: "short",
                  hour: "2-digit",
                  minute: "2-digit",
                })
              }
            />
            <Area
              dataKey="status"
              type="step"
              fill="var(--color-desktop)"
              fillOpacity={0.4}
              stroke="var(--color-desktop)"
            />
          </AreaChart>
        </ChartContainer>
      </CardContent>
    </Card>
  );
}

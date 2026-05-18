declare module "react-simple-maps" {
  import { ReactNode, CSSProperties, SVGAttributes } from "react";

  export interface ComposableMapProps {
    projection?: string;
    projectionConfig?: { scale?: number; center?: [number, number] };
    width?: number;
    height?: number;
    style?: CSSProperties;
    children?: ReactNode;
  }

  export const ComposableMap: (props: ComposableMapProps) => JSX.Element;

  export interface GeographiesProps {
    geography: string | object;
    children: (args: { geographies: any[] }) => ReactNode;
  }

  export const Geographies: (props: GeographiesProps) => JSX.Element;

  export interface GeographyProps extends SVGAttributes<SVGPathElement> {
    geography: any;
    style?: {
      default?: CSSProperties;
      hover?: CSSProperties;
      pressed?: CSSProperties;
    };
    children?: ReactNode;
  }

  export const Geography: (props: GeographyProps) => JSX.Element;
}

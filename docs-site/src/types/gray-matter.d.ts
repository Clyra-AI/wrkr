declare module 'gray-matter' {
  interface GrayMatterResult {
    data: Record<string, unknown>;
    content: string;
    orig: string;
  }

  export default function matter(input: string): GrayMatterResult;
}

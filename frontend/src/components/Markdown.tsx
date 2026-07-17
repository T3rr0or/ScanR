/**
 * Markdown — renders GitHub-flavored markdown (headings, lists, tables, code,
 * links) for AI agent messages and reports. The AI often replies in markdown;
 * this makes it display properly instead of as raw text.
 */
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

export default function Markdown({ children }: { children: string }) {
	return (
		<div className="md">
			<ReactMarkdown
				remarkPlugins={[remarkGfm]}
				components={{
					// Strip react-markdown's `node` prop — it is not a valid DOM attribute.
					a: ({ node: _node, ...props }) => (
						<a {...props} target="_blank" rel="noopener noreferrer" />
					),
				}}
			>
				{children}
			</ReactMarkdown>
		</div>
	);
}

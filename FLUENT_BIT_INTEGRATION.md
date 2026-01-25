\documentclass[11pt,a4paper]{article}
\usepackage[utf8]{inputenc}
\usepackage[margin=1in]{geometry}
\usepackage{hyperref}
\usepackage{listings}
\usepackage{xcolor}
\usepackage{enumitem}
\usepackage{booktabs}

% Code listing style
\lstdefinestyle{bash}{
    language=bash,
    basicstyle=\ttfamily\small,
    backgroundcolor=\color{gray!10},
    frame=single,
    breaklines=true,
    numbers=left,
    numberstyle=\tiny\color{gray},
    keywordstyle=\color{blue},
    commentstyle=\color{green!50!black},
    stringstyle=\color{red}
}

\lstdefinestyle{config}{
    basicstyle=\ttfamily\small,
    backgroundcolor=\color{gray!10},
    frame=single,
    breaklines=true,
    numbers=left,
    numberstyle=\tiny\color{gray}
}

\title{\textbf{Fluent-Bit Integration Guide}}
\author{LogGuard Documentation}
\date{\today}

\begin{document}

\maketitle

\tableofcontents
\newpage

\section{Introduction}
This guide explains how to integrate Fluent-Bit with LogGuard to start sending logs from your application servers.

\section{Prerequisites}
Before starting the integration, ensure you have:
\begin{itemize}
    \item A LogGuard account with an organization created
    \item API key from your organization dashboard
    \item Fluent-Bit installed on your application server
\end{itemize}

\section{Step 1: Get Your API Key}
\begin{enumerate}
    \item Log in to the LogGuard dashboard
    \item Navigate to \textbf{Settings} $\rightarrow$ \textbf{Organization}
    \item Copy your \textbf{API Key} (starts with \texttt{sk-})
\end{enumerate}

\section{Step 2: Install Fluent-Bit}

\subsection{Linux (Ubuntu/Debian)}
\begin{lstlisting}[style=bash]
curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh
\end{lstlisting}

\subsection{macOS}
\begin{lstlisting}[style=bash]
brew install fluent-bit
\end{lstlisting}

\subsection{Windows}
Download the installer from \href{https://github.com/fluent/fluent-bit/releases}{Fluent-Bit Releases}

\section{Step 3: Configure Fluent-Bit}
Create or edit the Fluent-Bit configuration file.

\subsection{Option A: Use the Provided Install Script}
We provide an installation script in the \texttt{fluent-bit/} folder:

\begin{lstlisting}[style=bash]
# Linux/macOS
cd fluent-bit
chmod +x install.sh
./install.sh

# Windows (PowerShell as Administrator)
cd fluent-bit
.\install.ps1
\end{lstlisting}

\subsection{Option B: Manual Configuration}
Create a configuration file (e.g., \texttt{fluent-bit.conf}):

\begin{lstlisting}[style=config]
[SERVICE]
    Flush        5
    Daemon       Off
    Log_Level    info

[INPUT]
    Name         tail
    Path         /var/log/nginx/access.log
    Tag          nginx.access
    Parser       nginx

[OUTPUT]
    Name         http
    Match        *
    Host         YOUR_LOGGUARD_SERVER_IP
    Port         80
    URI          /api/v1/logs/agent/send-logs
    Format       json
    Header       X-API-Key YOUR_API_KEY_HERE
\end{lstlisting}

Create a parsers file (\texttt{parsers.conf}):

\begin{lstlisting}[style=config]
[PARSER]
    Name         nginx
    Format       regex
    Regex        ^(?<remote>[^ ]*) (?<host>[^ ]*) (?<user>[^ ]*) 
                 \[(?<time>[^\]]*)\] "(?<method>\S+)(?: +(?<path>
                 [^\"]*?)(?: +\S*)?)?" (?<code>[^ ]*) (?<size>[^ ]*)
                 (?: "(?<referer>[^\"]*)" "(?<agent>[^\"]*)")?$
    Time_Key     time
    Time_Format  %d/%b/%Y:%H:%M:%S %z
\end{lstlisting}

\section{Step 4: Configure Your Log Source}

\subsection{For Nginx Access Logs}
Ensure your Nginx log format is set to combined format in \texttt{nginx.conf}:

\begin{lstlisting}[style=config]
http {
    log_format combined '$remote_addr - $remote_user [$time_local] '
                        '"$request" $status $body_bytes_sent '
                        '"$http_referer" "$http_user_agent"';
    
    access_log /var/log/nginx/access.log combined;
}
\end{lstlisting}

\subsection{For Apache Access Logs}
Update the INPUT section in Fluent-Bit config:

\begin{lstlisting}[style=config]
[INPUT]
    Name         tail
    Path         /var/log/apache2/access.log
    Tag          apache.access
\end{lstlisting}

\subsection{For Custom Application Logs}
\begin{lstlisting}[style=config]
[INPUT]
    Name         tail
    Path         /var/log/myapp/*.log
    Tag          myapp
\end{lstlisting}

\section{Step 5: Start Fluent-Bit}

\subsection{As a Service (Recommended)}
\begin{lstlisting}[style=bash]
sudo systemctl start fluent-bit
sudo systemctl enable fluent-bit
\end{lstlisting}

\subsection{Manual Start}
\begin{lstlisting}[style=bash]
fluent-bit -c /path/to/fluent-bit.conf -R /path/to/parsers.conf
\end{lstlisting}

\section{Step 6: Verify Integration}
\begin{enumerate}
    \item Generate some traffic on your application
    \item Check Fluent-Bit logs for successful sends:
    \begin{lstlisting}[style=bash]
journalctl -u fluent-bit -f
    \end{lstlisting}
    \item Log in to LogGuard dashboard to see incoming logs
\end{enumerate}

\section{Configuration Options}
\begin{table}[h]
\centering
\begin{tabular}{@{}lll@{}}
\toprule
\textbf{Setting} & \textbf{Description} & \textbf{Default} \\ \midrule
\texttt{Host} & LogGuard server IP/hostname & Required \\
\texttt{Port} & LogGuard server port & \texttt{80} \\
\texttt{URI} & Log ingestion endpoint & \texttt{/api/v1/logs/agent/send-logs} \\
\texttt{X-API-Key} & Your organization API key & Required \\
\texttt{Flush} & How often to send logs (seconds) & \texttt{5} \\ \bottomrule
\end{tabular}
\caption{Fluent-Bit Configuration Options}
\end{table}

\section{Supported Log Formats}
LogGuard automatically parses:
\begin{itemize}
    \item \textbf{Nginx access logs} (combined format)
    \item \textbf{Apache access logs} (combined format)
    \item \textbf{JSON structured logs}
    \item \textbf{Custom formats} (via raw log ingestion)
\end{itemize}

\section{Troubleshooting}

\subsection{Logs not appearing in dashboard}
\begin{enumerate}
    \item Check Fluent-Bit is running:
    \begin{lstlisting}[style=bash]
systemctl status fluent-bit
    \end{lstlisting}
    
    \item Verify API key is correct and active
    
    \item Check network connectivity:
    \begin{lstlisting}[style=bash]
curl -X POST http://YOUR_SERVER/api/v1/logs/agent/send-logs \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '[{"log": "test log message"}]'
    \end{lstlisting}
\end{enumerate}

\subsection{HTTP 401 Unauthorized}
\begin{itemize}
    \item API key is invalid or missing
    \item Check the \texttt{X-API-Key} header is correctly set
\end{itemize}

\subsection{HTTP 500 Internal Server Error}
\begin{itemize}
    \item Check server logs for details
    \item Verify log format matches expected structure
\end{itemize}

\section{Support}
For issues or questions:
\begin{itemize}
    \item Check the main README.md
    \item Open an issue on GitHub
    \item Contact your organization administrator
\end{itemize}

\end{document}

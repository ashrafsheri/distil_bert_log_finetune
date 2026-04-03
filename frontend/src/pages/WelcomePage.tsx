import React from 'react';
import { Link } from 'react-router-dom';

const featureCards = [
  {
    title: 'Live Threat Monitoring',
    copy: 'Inspect suspicious traffic in realtime, pause the stream when needed, and review queued events without losing continuity.',
    accent: 'from-sky-500/20 to-cyan-400/10 text-sky-300',
  },
  {
    title: 'Explainable Detection',
    copy: 'See ensemble decisions, transformer context, parse failures, and incident grouping in one operational surface.',
    accent: 'from-emerald-500/20 to-teal-400/10 text-emerald-300',
  },
  {
    title: 'Multi-Tenant Control',
    copy: 'Manage organizations, users, projects, and project readiness from a single premium security operations workspace.',
    accent: 'from-fuchsia-500/20 to-violet-400/10 text-fuchsia-300',
  },
];

const WelcomePage: React.FC = () => {
  return (
    <div className="relative overflow-hidden">
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute left-0 top-0 h-80 w-80 rounded-full bg-sky-500/12 blur-3xl" />
        <div className="absolute right-0 top-20 h-96 w-96 rounded-full bg-cyan-400/8 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-72 w-72 rounded-full bg-fuchsia-500/8 blur-3xl" />
      </div>

      <div className="relative mx-auto flex min-h-[calc(100vh-81px)] max-w-[1600px] items-center px-4 py-14 sm:px-6 lg:px-8">
        <div className="grid w-full gap-8 xl:grid-cols-[minmax(0,1.15fr)_420px]">
          <section className="rounded-[32px] border border-white/6 bg-[linear-gradient(180deg,rgba(15,23,42,0.96),rgba(8,15,29,0.94))] p-8 shadow-[0_28px_80px_rgba(2,8,23,0.45)] lg:p-12">
            <div className="inline-flex items-center gap-2 rounded-full border border-sky-400/18 bg-sky-500/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-sky-200">
              Security Operations Platform
            </div>

            <div className="mt-8 max-w-4xl">
              <h1 className="text-5xl font-semibold tracking-tight text-slate-50 sm:text-6xl xl:text-7xl">
                Operational clarity for live log detection and incident review.
              </h1>
              <p className="mt-6 max-w-3xl text-lg leading-8 text-slate-300 sm:text-xl">
                LogGuard is a premium monitoring workspace for security teams and platform engineers. Connect logs, inspect detections, manage projects, and keep anomaly review explainable under live traffic.
              </p>
            </div>

            <div className="mt-10 flex flex-wrap gap-4">
              <Link
                to="/projects"
                className="inline-flex items-center justify-center rounded-2xl bg-gradient-to-r from-sky-500 to-cyan-400 px-6 py-3.5 text-sm font-semibold text-white shadow-[0_18px_38px_rgba(14,165,233,0.22)] transition hover:translate-y-[-1px] hover:shadow-[0_24px_48px_rgba(14,165,233,0.3)]"
              >
                Open Projects
              </Link>
              <Link
                to="/login"
                className="inline-flex items-center justify-center rounded-2xl border border-white/10 bg-white/[0.03] px-6 py-3.5 text-sm font-semibold text-slate-200 transition hover:border-white/16 hover:bg-white/[0.05]"
              >
                Sign In
              </Link>
            </div>

            <div className="mt-12 grid gap-4 lg:grid-cols-3">
              {featureCards.map(card => (
                <article
                  key={card.title}
                  className="rounded-3xl border border-white/6 bg-white/[0.025] p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.02)]"
                >
                  <div className={`inline-flex rounded-2xl bg-gradient-to-br px-3 py-2 text-sm font-medium ${card.accent}`}>
                    {card.title}
                  </div>
                  <p className="mt-4 text-sm leading-7 text-slate-400">{card.copy}</p>
                </article>
              ))}
            </div>
          </section>

          <aside className="grid gap-5">
            <div className="rounded-[30px] border border-white/6 bg-[linear-gradient(180deg,rgba(12,20,38,0.96),rgba(8,15,29,0.94))] p-7 shadow-[0_24px_60px_rgba(2,8,23,0.42)]">
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">Platform snapshot</p>
              <div className="mt-6 grid gap-4">
                <div className="rounded-2xl border border-white/6 bg-white/[0.03] p-5">
                  <div className="text-sm text-slate-500">Ensemble models</div>
                  <div className="mt-2 text-4xl font-semibold text-slate-50">3</div>
                  <div className="mt-2 text-sm text-slate-400">Rule-based, isolation forest, and transformer scoring.</div>
                </div>
                <div className="rounded-2xl border border-white/6 bg-white/[0.03] p-5">
                  <div className="text-sm text-slate-500">Response path</div>
                  <div className="mt-2 text-4xl font-semibold text-emerald-300">&lt;10ms</div>
                  <div className="mt-2 text-sm text-slate-400">Realtime websocket ingestion and queue-based review controls.</div>
                </div>
              </div>
            </div>

            <div className="rounded-[30px] border border-white/6 bg-[linear-gradient(180deg,rgba(12,20,38,0.96),rgba(8,15,29,0.94))] p-7 shadow-[0_24px_60px_rgba(2,8,23,0.42)]">
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">Built for</p>
              <ul className="mt-5 space-y-4 text-sm text-slate-300">
                <li className="rounded-2xl border border-white/6 bg-white/[0.03] px-4 py-4">Security teams reviewing suspicious traffic and grouped incidents.</li>
                <li className="rounded-2xl border border-white/6 bg-white/[0.03] px-4 py-4">Platform engineers managing warmup, log parsing, and model readiness.</li>
                <li className="rounded-2xl border border-white/6 bg-white/[0.03] px-4 py-4">Admins coordinating organizations, users, projects, and production access.</li>
              </ul>
            </div>
          </aside>
        </div>
      </div>
    </div>
  );
};

export default WelcomePage;

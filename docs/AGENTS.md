# Git 작업 규칙 (Claude Code용)

이 문서는 Claude Code가 이 저장소에서 git 관련 작업(commit, branch, push, pull, merge)을 수행할 때 반드시 따라야 하는 규칙입니다.

## 0. 기본 원칙

- **원격에 영향을 주는 작업(push, force-push, merge, branch 삭제)은 실행 전에 사용자에게 계획을 먼저 설명하고 확인받는다.**
- 설명 및 해석을 수행하는 언어는 한국어다.
- 확실하지 않은 상황(충돌, 이력 재작성 등)에서는 임의로 판단하지 말고 상황을 설명한 뒤 사용자에게 묻는다.
- `git status`, `git diff`, `git log` 등 읽기 전용 명령은 자유롭게 실행해도 된다.

## 1. Commit 규칙

### 1-1. 형식

- 커밋 메시지는 **Conventional Commits** 형식을 따른다.
  ```
  <type>(<scope>): <subject>

  <body (선택)>

  <footer (선택)>
  ```

### 1-2. type 종류

| type | 의미 |
|---|---|
| `feat` | 새로운 기능 추가 |
| `fix` | 버그 수정 |
| `refactor` | 기능 변경 없는 코드 구조 개선 |
| `docs` | 문서 변경 (README, 주석 등) |
| `style` | 코드 포맷팅, 세미콜론 등 동작에 영향 없는 변경 |
| `test` | 테스트 추가/수정 |
| `chore` | 빌드, 패키지 설정 등 기타 잡무 |
| `perf` | 성능 개선 |
| `ci` | CI/CD 설정 변경 |
| `revert` | 이전 커밋 되돌리기 |

### 1-3. scope

- 변경이 영향을 미치는 모듈/디렉터리/기능 단위를 소문자로 작성 (예: `auth`, `api`, `ui`, `db`).
- 범위가 애매하거나 전역적인 변경이면 생략 가능: `fix: 빌드 스크립트 경로 오류 수정`.

### 1-4. subject (제목)

- 50자 이내로 간결하게 작성.
- 명령형/현재형으로 작성하고 끝에 마침표를 붙이지 않는다.
  - 좋은 예: `fix(auth): 토큰 만료 시 재발급 로직 수정`
  - 나쁜 예: `버그를 수정했습니다.`
- "무엇을" 했는지가 드러나야 하며, "여러 가지 수정" 같은 모호한 표현은 금지.

### 1-5. body (본문)

- 변경이 복잡하거나 "왜" 이 변경이 필요한지 설명이 필요할 때 작성.
- 무엇을(what) 보다 **왜(why)** 와 **어떻게(how)** 중심으로 작성.
- 제목과 본문 사이에는 빈 줄 하나를 둔다.
- 여러 항목이면 `-` 불릿으로 나열.

### 1-6. footer (꼬리말)

- 이슈 연결: `Closes #12`, `Refs #34`, `Related to #56`
- Breaking change가 있으면 `BREAKING CHANGE: <설명>`으로 명시.

### 1-7. 기타 규칙

- 하나의 커밋은 하나의 논리적 변경만 포함한다. 여러 목적의 변경이 섞여 있으면 나눠서 커밋할 것을 제안한다.
- 커밋 전 반드시 `git diff --staged`로 변경 내용을 확인하고 의도한 파일만 포함되었는지 검증한다.
- **불필요한 파일은 커밋하지 않는다**: `.env`, `node_modules`, 빌드 산출물, IDE 설정 파일 등은 `.gitignore`에 있는지 확인.
- 커밋 메시지에 "Generated with Claude Code" 같은 서명을 넣을지 여부는 사용자 지시를 따른다 (기본은 넣지 않음).
- **절대 `git commit --amend`나 `git rebase`로 이미 push된 커밋의 이력을 바꾸지 않는다** (사용자가 명시적으로 요청한 경우 제외).

## 2. Branch 관리 규칙

- 브랜치 이름 규칙:
  - 기능 개발: `feature/<설명>` (예: `feature/user-auth`)
  - 버그 수정: `fix/<설명>`
  - 긴급 수정: `hotfix/<설명>`
  - 리팩토링: `refactor/<설명>`
- **`main`(또는 `master`) 브랜치에서 직접 작업하지 않는다.** 새 작업은 항상 새 브랜치를 만들어서 진행한다.
- 브랜치 생성 전 `git status`로 현재 작업 트리가 깨끗한지 확인한다. 커밋되지 않은 변경사항이 있으면 사용자에게 stash 또는 커밋 여부를 확인한다.
- 브랜치를 만들기 전에 최신 `main`을 기준으로 하는지 확인한다:
  ```
  git checkout main
  git pull origin main
  git checkout -b feature/xxx
  ```

## 3. Push / Pull 규칙

- **`push` 실행 전에 반드시 어떤 브랜치로, 어떤 커밋들이 push되는지 요약해서 보여주고 확인받는다.**
- `git push --force`는 **원칙적으로 금지**. 정말 필요한 경우(자신의 feature 브랜치를 rebase한 직후 등)에는 `--force-with-lease`를 사용하고, 반드시 사용자 승인 후에만 실행한다.
- `main`/`master`/`develop` 등 공유 브랜치에는 **절대 force push 하지 않는다.**
- `pull` 시 기본적으로 `git pull --ff-only` 또는 `git pull --rebase`를 사용하고, merge commit이 자동 생성되는 상황을 피한다 (사용자가 merge 방식을 선호하면 그에 따름).
- pull 전에 로컬에 커밋되지 않은 변경사항이 있으면 사용자에게 알리고 stash 여부를 확인한다.

## 4. Merge 규칙

- feature 브랜치를 `main`에 합칠 때는 기본적으로 **Pull Request(또는 사용자 지시에 따른 방식)** 를 우선한다. 로컬에서 바로 merge하는 경우:
  ```
  git checkout main
  git pull origin main
  git merge --no-ff feature/xxx
  ```
  `--no-ff`를 사용해 병합 이력을 남긴다 (squash 병합을 원하면 사용자가 명시적으로 요청).
- **merge 충돌 발생 시 자동으로 임의 해결하지 않는다.** 충돌 파일 목록과 충돌 내용을 보여주고, 어떻게 해결할지 사용자와 상의한다.
- merge 완료 후 병합에 사용된 feature 브랜치를 삭제할지는 사용자에게 확인 후 진행한다.

## 5. 안전장치 (공통)

- 다음 명령은 **사용자의 명시적 승인 없이 절대 실행하지 않는다**:
  - `git push --force` (`--force-with-lease` 포함)
  - `git reset --hard`
  - `git rebase` (특히 이미 공유된 브랜치)
  - `git branch -D` / `git push origin --delete`
  - `git clean -fd`
- 작업 전후로 `git status`, `git log --oneline -5` 등을 통해 현재 상태를 사용자에게 공유한다.
- 커밋 메시지, 브랜치명, PR 제목 등은 프로젝트의 기존 컨벤션이 있다면 그것을 우선한다 (과거 `git log` 이력을 참고해서 스타일을 맞춘다).

## 6. Issue 규칙 (GitHub Issue 사용 시)

### 6-1. 제목 (Title)

- 형식: `[<type>] <요약>`
  - type 예시: `Bug`, `Feature`, `Improvement`, `Docs`, `Question`, `Chore`
  - 예: `[Bug] 로그인 시 세션 만료 오류 발생`, `[Feature] 다크 모드 지원 추가`
- 50자 내외로 핵심만 담고, "확인 필요", "이상함" 같은 모호한 표현 금지.
- 재현 가능한 버그라면 제목에 **증상**을 구체적으로 명시 (예: "느림" X → "목록 조회 API 응답 3초 이상 지연" O).

### 6-2. 본문 (Body) 템플릿

**버그 리포트**
```markdown
## 현상
무엇이 잘못되었는지 설명

## 재현 방법
1. ...
2. ...

## 기대 동작
원래 어떻게 동작해야 하는지

## 실제 동작
현재 어떻게 동작하는지 (에러 로그, 스크린샷 등 첨부)

## 환경
- OS / 브라우저 / 버전 등
```

**기능 요청**
```markdown
## 배경 / 문제
왜 이 기능이 필요한지

## 제안 **내용**
어떤 기능/변경을 원하는지

## 대안
고려했던 다른 방법 (있다면)
```

### 6-3. 라벨 / 담당 규칙

- 가능하면 라벨을 부여한다: `bug`, `enhancement`, `documentation`, `question`, `wontfix` 등.
- 우선순위가 필요하면 `priority: high/medium/low` 라벨 사용.
- 이슈 생성 전 유사한 이슈가 이미 있는지 검색해보고 중복이면 기존 이슈에 코멘트로 추가하는 것을 우선한다.

### 6-4. Issue ↔ Commit/PR 연결

- 커밋 footer나 PR 본문에서 `Closes #<번호>` / `Fixes #<번호>` 로 연결해 머지 시 이슈가 자동으로 닫히도록 한다.
- 이슈 하나에 여러 PR이 걸릴 수 있는 큰 작업은 `Refs #<번호>`로 연결만 하고 자동 닫힘은 피한다.

## 7. Pull Request (선택 사항, GitHub 사용 시)

- PR 제목은 커밋 컨벤션과 동일한 `<type>(<scope>): <subject>` 형식을 따른다.
- PR 본문 템플릿:
  ```markdown
  ## 변경 사항
  - ...

  ## 이유 / 배경
  - ...

  ## 테스트
  - [ ] 로컬에서 테스트 완료
  - [ ] 관련 테스트 코드 추가/수정

  ## 관련 이슈
  Closes #<번호>
  ```
- PR 생성 전 반드시 diff 내용을 요약해서 사용자에게 보여주고 확인받는다.
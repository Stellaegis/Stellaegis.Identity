# Third-party notices

Stellaegis.Identity is licensed under the MIT License (see [LICENSE](LICENSE)).

Its packages contain no third-party code. They reference the packages below, which NuGet installs
alongside them, each under its own license. The table is completed as the packages are written.

| Component | Used by | License (SPDX) | Project |
| --- | --- | --- | --- |
| Stellaegis.Primitives, and Stellaegis.Primitives.Hosting | all packages | MIT | <https://github.com/Stellaegis/Stellaegis.Primitives> |
| Stellaegis.Primitives.Data | `Stellaegis.Identity.PostgreSQL` | MIT | <https://github.com/Stellaegis/Stellaegis.Primitives> |
| Stellaegis.Primitives.AspNetCore | `Stellaegis.Identity.AspNetCore` | MIT | <https://github.com/Stellaegis/Stellaegis.Primitives> |
| qrcode.js (`qrcode.min.js`, served by the pages to draw the QR code of an authenticator enrollment) | `Stellaegis.Identity.Server` | MIT | <https://github.com/davidshimjs/qrcodejs> |
| Otp.NET | `Stellaegis.Identity` | MIT | <https://github.com/kspearrin/Otp.NET> |
| Npgsql | `Stellaegis.Identity.PostgreSQL` | PostgreSQL | <https://github.com/npgsql/npgsql> |
| Dapper | `Stellaegis.Identity.PostgreSQL` | Apache-2.0 | <https://github.com/DapperLib/Dapper> |
| Microsoft.Extensions.\* | all packages | MIT | <https://github.com/dotnet> |

`Stellaegis.Identity.AspNetCore` and `Stellaegis.Identity.Server` use the ASP.NET Core shared framework, which the host already has. `Stellaegis.Identity.Server` is the one package that contains third-party code: `qrcode.min.js`, copied as is.

Test-only dependencies (xUnit, the ASP.NET Core test host) are not part of any package and are not
listed here. The PostgreSQL server that the tests and the publishing workflow use is not part of any
package either.
